using Microsoft.AspNetCore.Server.Kestrel;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.AspNetCore.Server.Kestrel.Https;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Runtime.CompilerServices;

namespace ServerCertificateChain.Kestrel
{
    /// <summary>
    /// kestrel的一些反射访问扩展方法
    /// </summary>
    static class KestrelReflectionExtensions
    {
        [UnsafeAccessor(UnsafeAccessorKind.Method, Name = "get_EndpointDefaults")]
        private static extern Action<ListenOptions> GetEndpointDefaults(KestrelServerOptions kestrel);

        [UnsafeAccessor(UnsafeAccessorKind.Method, Name = "get_HttpsDefaults")]
        private static extern Action<HttpsConnectionAdapterOptions> GetHttpsDefaults(KestrelServerOptions kestrel);

        [UnsafeAccessor(UnsafeAccessorKind.Method, Name = "get_EndpointConfigurations")]
        private static extern IDictionary<string, Action<EndpointConfiguration>> GetEndpointConfigurations(KestrelConfigurationLoader loader);

        private static readonly ConcurrentDictionary<HttpsConnectionAdapterOptions, AuthenticateBuilder> _authenticateBuilderCache = new();

        extension(KestrelServerOptions kestrel)
        {
            public Action<ListenOptions> EndpointDefaults => GetEndpointDefaults(kestrel);

            public Action<HttpsConnectionAdapterOptions> HttpsDefaults => GetHttpsDefaults(kestrel);
        }

        extension(KestrelConfigurationLoader loader)
        {
            public IDictionary<string, Action<EndpointConfiguration>> EndpointConfigurations => GetEndpointConfigurations(loader);
        }

        extension(HttpsConnectionAdapterOptions options)
        {
            public AuthenticateBuilder AuthenticateBuilder => _authenticateBuilderCache.GetOrAdd(options, _ => new AuthenticateBuilder());
        }
    }
}
