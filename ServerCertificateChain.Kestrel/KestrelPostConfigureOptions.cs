using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.Extensions.Options;
using System;

namespace ServerCertificateChain.Kestrel
{
    /// <summary>
    /// KestrelServerOptions 的后置配置选项，用于在 KestrelServerOptions 配置完成后
    /// 定义新类型，目的是防止多次注册导致的重复配置问题。
    /// </summary>
    sealed class KestrelPostConfigureOptions : PostConfigureOptions<KestrelServerOptions>
    {
        public KestrelPostConfigureOptions(Action<KestrelServerOptions>? action)
            : base(Options.DefaultName, action)
        {
        }
    }
}
