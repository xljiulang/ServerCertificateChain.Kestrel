using Microsoft.AspNetCore.Connections;
using System;
using System.Collections.Generic;
using System.Net.Security;

namespace ServerCertificateChain.Kestrel
{
    sealed class AuthenticateBuilder
    {
        private readonly Action<ConnectionContext, SslServerAuthenticationOptions> _fallbackHandler = (_, _) => { };
        private readonly List<Func<Action<ConnectionContext, SslServerAuthenticationOptions>, Action<ConnectionContext, SslServerAuthenticationOptions>>> _middlewares = [];

        public void UseUserAuthenticate(Action<ConnectionContext, SslServerAuthenticationOptions>? useOnAuthenticate, Action<SslServerAuthenticationOptions> configureOptions)
        {
            if (this._middlewares.Count == 0)
            {
                this._middlewares.Add(next => (context, options) =>
                {
                    useOnAuthenticate?.Invoke(context, options);
                    configureOptions.Invoke(options);
                    next.Invoke(context, options);
                });
            }
        }

        public void UseCustomAuthenticate(Func<Action<ConnectionContext, SslServerAuthenticationOptions>, Action<ConnectionContext, SslServerAuthenticationOptions>> middleware)
        {
            if (this._middlewares.Count == 0)
            {
                throw new InvalidOperationException($"Custom authenticate middleware must be added after {nameof(UseUserAuthenticate)}().");
            }

            // 自定义的认证中间件们要倒序执行
            // 最终顺序是: UserAuthenticate -> EndpointAuthenticate -> DefaultAuthenticate
            this._middlewares.Insert(1, middleware);
        }

        public Action<ConnectionContext, SslServerAuthenticationOptions> Build()
        {
            var handler = this._fallbackHandler;
            for (var i = this._middlewares.Count - 1; i >= 0; i--)
            {
                handler = this._middlewares[i].Invoke(handler);
            }
            return handler;
        }
    }
}
