using Microsoft.AspNetCore.Server.Kestrel;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.AspNetCore.Server.Kestrel.Https;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Primitives;
using ServerCertificateChain.Kestrel;
using System;
using System.Collections.Frozen;
using System.Linq;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;

namespace Microsoft.AspNetCore.Hosting
{
    /// <summary>
    /// <see cref="HttpsConnectionAdapterOptions"/> 的扩展方法
    /// </summary>
    public static partial class WebHostBuilderExtensions
    {
        /// <summary>
        /// 用户的每个Endpoint配置代码
        /// </summary>
        private static FrozenDictionary<string, Action<EndpointConfiguration>>? _userEndpointConfigurations;

        /// <summary>
        /// 从叶子证书到证书上下文的缓存，避免为每个连接重复创建证书链上下文。
        /// </summary>
        private static readonly ConcurrentCache<X509Certificate2, SslStreamCertificateContext> _certificateContextCache = new();

        /// <summary>
        /// 从证书配置到证书链的缓存，避免为每个连接都从配置中重新加载证书链。
        /// </summary>
        private static readonly ConcurrentCache<CertificateConfigSection, X509Certificate2Collection?> _certificateChainCache = new();

        /// <summary>
        /// 通过 <see cref="HttpsConnectionAdapterOptions.ServerCertificateChain"/> 完全创建自定义服务器证书链。
        /// <para>* 规避 Kestrel 未加载配置中默认证书证书链的问题 https://github.com/dotnet/aspnetcore/pull/60710</para>
        /// <para>* 规避 Kestrel 未加载配置中非 PEM 端点证书（如 PFX 文件）证书链的问题 https://github.com/dotnet/aspnetcore/blob/v10.0.9/src/Servers/Kestrel/Core/src/Internal/Certificates/CertificateConfigLoader.cs#L42</para>
        /// <para>* 规避 Kestrel 的 HTTPS 中间件使用中间证书创建 <see cref="SslStreamCertificateContext"/> 时，在某些系统上可能将交叉证书视为根证书的问题 https://github.com/dotnet/aspnetcore/blob/v10.0.9/src/Servers/Kestrel/Core/src/Middleware/HttpsConnectionMiddleware.cs#L112</para>
        /// </summary>
        /// <param name="builder"></param>
        /// <returns></returns>
        public static IWebHostBuilder UseKestrelCustomServerCertificateChain(this IWebHostBuilder builder)
        {
            builder.ConfigureServices(services => services.PostConfigure<KestrelServerOptions>(kestrel =>
            {
                kestrel.ConfigurationLoader ??= kestrel.Configure();
                var configurationLoader = kestrel.ConfigurationLoader;
                var logger = kestrel.ApplicationServices.GetService<ILoggerFactory>()?.CreateLogger("ServerCertificateChain.Kestrel") ?? NullLogger.Instance;

                // 配置变更时清空缓存。
                ChangeToken.OnChange(configurationLoader.Configuration.GetReloadToken, () =>
                {
                    _certificateChainCache.Clear();
                    _certificateContextCache.Clear();
                });

                // 用户的 HTTPS 公共配置代码
                var userHttpsDefaults = kestrel.HttpsDefaults;
                kestrel.ConfigureHttpsDefaults(https =>
                {
                    userHttpsDefaults.Invoke(https);

                    var defaultCertificateSession = configurationLoader.Configuration.GetSection("Certificates:Default");
                    UseCustomServerCertificateChain(https, defaultCertificateSession, logger);
                });

                // 为各个终结点配置 HTTPS 默认值。
                kestrel.ConfigureEndpointHttpsDefaults(configurationLoader, endpont =>
                {
                    var endpointCertificateSession = endpont.ConfigSection.GetSection("Certificate");
                    UseCustomServerCertificateChain(endpont.HttpsOptions, endpointCertificateSession, logger);
                });
            }));
            return builder;
        }

        /// <summary>
        /// 配置终结点默认值，以支持每个终结点使用不同的服务器证书链。该回调会在 <c>ConfigureHttpsDefaults</c> 之后执行。
        /// </summary>
        /// <param name="kestrel"></param>
        /// <param name="loader"></param>
        /// <param name="configureOptions"></param>
        private static void ConfigureEndpointHttpsDefaults(this KestrelServerOptions kestrel, KestrelConfigurationLoader loader, Action<EndpointConfiguration> configureOptions)
        {
            // 用户的 Endpoint 公共配置代码
            var userEndpointDefaults = kestrel.EndpointDefaults;
            kestrel.ConfigureEndpointDefaults(listener =>
            {
                userEndpointDefaults.Invoke(listener);

                // 把首次获取的每个 Endpoint 的配置缓存下来，后续每次配置 Endpoint 时都基于用户的原始配置进行重新创建
                var endpointConfigurations = loader.EndpointConfigurations;
                _userEndpointConfigurations ??= endpointConfigurations.ToFrozenDictionary();

                foreach (var endpointSection in loader.Configuration.GetSection("Endpoints").GetChildren())
                {
                    var endpointName = endpointSection.Key;
                    _userEndpointConfigurations.TryGetValue(endpointName, out var userEndpointConfiguration);

                    endpointConfigurations[endpointName] = endpoint =>
                    {
                        userEndpointConfiguration?.Invoke(endpoint);
                        if (endpoint.IsHttps)
                        {
                            configureOptions.Invoke(endpoint);
                        }
                    };
                }
            });
        }

        /// <summary>
        /// 通过 <see cref="HttpsConnectionAdapterOptions.ServerCertificateChain"/> 完全创建自定义服务器证书链。
        /// </summary>
        /// <param name="https"></param>
        /// <param name="certificateSession"></param> 
        /// <exception cref="InvalidOperationException"></exception>
        private static void UseCustomServerCertificateChain(HttpsConnectionAdapterOptions https, IConfigurationSection certificateSession, ILogger logger)
        {
            var builder = https.AuthenticateBuilder;
            builder.UseUserAuthenticate(https.OnAuthenticate, options =>
            {
                if (options.ServerCertificateSelectionCallback != null)
                {
                    // 这似乎是 SslStream 的一个限制。
                    // 配置了 ServerCertificateSelectionCallback 时，
                    // 无法为所选服务器证书指定对应的 ServerCertificateChain，因此不能使用 UseCustomServerCertificateChain。
                    throw new InvalidOperationException($"已配置 {nameof(HttpsConnectionAdapterOptions.ServerCertificateSelector)}，因此不能使用 {nameof(UseCustomServerCertificateChain)}。");
                }
            });

            builder.UseCustomAuthenticate(next => (context, options) =>
            {
                if (options.ServerCertificate is not X509Certificate2 serverCertificate)
                {
                    throw new InvalidOperationException($"未配置 {nameof(HttpsConnectionAdapterOptions.ServerCertificate)}，因此不能使用 {nameof(UseCustomServerCertificateChain)}。");
                }

                // 必须在 OnAuthenticate 回调中读取 ServerCertificateChain，而不是在 ConfigureHttpsDefaults 回调中读取。
                var serverCertificateChain = https.ServerCertificateChain;
                if (serverCertificateChain == null || serverCertificateChain.Count == 0)
                {
                    // https://github.com/dotnet/aspnetcore/pull/60710
                    // Kestrel 问题 1（已在 ASP.NET Core 11 修复）：当终结点未配置证书而使用默认证书时，不会分配证书链，因此 serverCertificateChain == null。

                    // https://github.com/dotnet/aspnetcore/blob/v10.0.9/src/Servers/Kestrel/Core/src/Internal/Certificates/CertificateConfigLoader.cs#L42
                    // Kestrel 问题 2：当终结点下配置的是 bundle.pfx 之类的文件证书而不是 PEM 证书时，不会加载中间证书链，因此 serverCertificateChain.Count == 0。

                    // 尝试从配置中加载服务器证书链，并回写到 https.ServerCertificateChain 以供后续使用。
                    var cacheKey = new CertificateConfigSection(serverCertificate, certificateSession);
                    serverCertificateChain = _certificateChainCache.GetOrAdd(cacheKey, section =>
                    {
                        var certificateChain = section.LoadCertificateChain();
                        if (certificateChain != null)
                        {
                            Log.ServerCertificateChainLoaded(logger, serverCertificate.Subject, certificateSession.Path);
                        }
                        return certificateChain;
                    });

                    // 更新回 https.ServerCertificateChain，以便后续的连接有可能直接使用，从而避免从 _certificateChainCache 查找。
                    https.ServerCertificateChain = serverCertificateChain;
                }

                if (serverCertificateChain == null || serverCertificateChain.Count == 0)
                {
                    Log.ServerCertificateChainLoadFailed(logger, serverCertificate.Subject, certificateSession.Path);
                    next.Invoke(context, options);
                    return;
                }

                // 这里需要缓存以保证性能，因为每个客户端的连接都会创建新的 options 实例。
                options.ServerCertificateContext = _certificateContextCache.GetOrAdd(serverCertificate, _ =>
                {
                    var certificateContext = CreateCustomServerCertificateContext(serverCertificate, serverCertificateChain, options.ServerCertificateContext);
                    Log.CustomServerCertificateContextCreated(logger, serverCertificate.Subject, certificateContext.IntermediateCertificates.Count);
                    return certificateContext;
                });
            });

            https.OnAuthenticate = builder.Build();
        }


        /// <summary>
        /// 创建一个使用自定义服务器证书链的 <see cref="SslStreamCertificateContext"/>。
        /// </summary>
        /// <param name="serverCertificate"></param>
        /// <param name="serverCertificateChain"></param>
        /// <param name="systemServerCertificateContext"></param>
        /// <returns></returns>
        private static SslStreamCertificateContext CreateCustomServerCertificateContext(
            X509Certificate2 serverCertificate,
            X509Certificate2Collection serverCertificateChain,
            SslStreamCertificateContext? systemServerCertificateContext)
        {
            // 如果没有中间证书，则优先直接使用系统创建的证书上下文；如果没有，再创建一个由系统推断的新上下文。
            if (serverCertificateChain.Any(i => i.Thumbprint != serverCertificate.Thumbprint) == false)
            {
                return systemServerCertificateContext ?? SslStreamCertificateContext.Create(serverCertificate, null);
            }

            // 无需检查 systemServerCertificateContext 中的中间证书链是否与 intermediateCertificates 匹配。
            // 一切都以 intermediateCertificates 为准，因为它来自用户配置，生成的证书链应与用户配置保持一致。
            var certificateTrust = SslCertificateTrust.CreateForX509Collection(serverCertificateChain);
            return SslStreamCertificateContext.Create(serverCertificate, null, false, certificateTrust);
        }

        private static partial class Log
        {
            [LoggerMessage(Level = LogLevel.Information, Message = "Successfully loaded the server certificate chain from '{endpointPath}' for '{serverCertificateSubject}'.")]
            public static partial void ServerCertificateChainLoaded(ILogger logger, string serverCertificateSubject, string endpointPath);

            [LoggerMessage(Level = LogLevel.Warning, Message = "Failed to load the server certificate chain from '{endpointPath}' for '{serverCertificateSubject}'.")]
            public static partial void ServerCertificateChainLoadFailed(ILogger logger, string serverCertificateSubject, string endpointPath);

            [LoggerMessage(Level = LogLevel.Information, Message = "Successfully created a custom certificate context for '{serverCertificateSubject}' with {intermediateCertificateCount} intermediate certificates.")]
            public static partial void CustomServerCertificateContextCreated(ILogger logger, string serverCertificateSubject, int intermediateCertificateCount);
        }
    }
}