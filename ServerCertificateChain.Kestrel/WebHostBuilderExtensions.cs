using Microsoft.AspNetCore.Server.Kestrel;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.AspNetCore.Server.Kestrel.Https;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using ServerCertificateChain.Kestrel;
using System;
using System.Collections.Frozen;
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
            var _userEndpointConfigurations = default(FrozenDictionary<string, Action<EndpointConfiguration>>);

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

                var chain = https.ServerCertificateChain as X509Certificate2Chain;
                if (chain == null)
                {
                    chain = CreateCertificate2Chain(serverCertificate, https.ServerCertificateChain, certificateSession, logger);
                    https.ServerCertificateChain = chain;
                }

                if (chain == null)
                {
                    Log.ServerCertificateChainLoadFailed(logger, serverCertificate.Subject, certificateSession.Path);
                    next.Invoke(context, options);
                    return;
                }

                if (chain.CertificateContext.IsValueCreated == false)
                {
                    Log.CustomServerCertificateContextCreated(logger, serverCertificate.Subject, chain.Count);
                }
                options.ServerCertificateContext = chain.CertificateContext.Value;
            });

            https.OnAuthenticate = builder.Build();
        }

        private static X509Certificate2Chain? CreateCertificate2Chain(
            X509Certificate2 certificate,
            X509Certificate2Collection? serverCertificateChain,
            IConfigurationSection certificateSession,
            ILogger logger)
        {
            // https://github.com/dotnet/aspnetcore/pull/60710
            // Kestrel 问题 1（已在 ASP.NET Core 11 修复）：当终结点未配置证书而使用默认证书时，不会分配证书链，因此 serverCertificateChain == null。

            // https://github.com/dotnet/aspnetcore/blob/v10.0.9/src/Servers/Kestrel/Core/src/Internal/Certificates/CertificateConfigLoader.cs#L42
            // Kestrel 问题 2：当终结点下配置的是 bundle.pfx 之类的文件证书而不是 PEM 证书时，不会加载中间证书链，因此 serverCertificateChain.Count == 0。
            if (serverCertificateChain == null || serverCertificateChain.Count == 0)
            {
                var chain = X509Certificate2Chain.ParseFromConfigSection(certificate, certificateSession);
                if (chain != null)
                {
                    Log.ServerCertificateChainLoaded(logger, certificate.Subject, certificateSession.Path);
                }
                return chain;
            }

            return new X509Certificate2Chain(certificate, serverCertificateChain);
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