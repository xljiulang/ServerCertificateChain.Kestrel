using Microsoft.AspNetCore.Connections;
using System;
using System.Collections.Generic;
using System.Net.Security;

namespace ServerCertificateChain.Kestrel
{
    /// <summary>
    /// ssl 认证构建器，负责构建一个认证处理器，该处理器会在 Kestrel 的 HTTPS 中间件中被调用，以配置 SSL 认证选项。
    /// </summary>
    sealed class AuthenticateBuilder
    {
        private readonly Action<ConnectionContext, SslServerAuthenticationOptions> _fallbackHandler = (_, _) => { };
        private readonly List<Func<Action<ConnectionContext, SslServerAuthenticationOptions>, Action<ConnectionContext, SslServerAuthenticationOptions>>> _middlewares = [];

        /// <summary>
        /// 使用用户的认证逻辑来配置 SSL 认证选项。该方法只能调用一次，并且必须在任何自定义认证中间件之前调用。
        /// </summary>
        /// <param name="useOnAuthenticate">用户认证逻辑</param>
        /// <param name="configureOptions">额外配置</param>
        public void UseUserAuthenticate(
            Action<ConnectionContext, SslServerAuthenticationOptions>? useOnAuthenticate,
            Action<SslServerAuthenticationOptions> configureOptions)
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

        /// <summary>
        /// 使用自定义的认证中间件来配置 SSL 认证选项
        /// </summary>
        /// <param name="middleware"></param>
        /// <exception cref="InvalidOperationException"></exception>
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

        /// <summary>
        /// 创建一个认证处理器，该处理器会在 Kestrel 的 HTTPS 中间件中被调用，以配置 SSL 认证选项。
        /// </summary>
        /// <returns></returns>
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
