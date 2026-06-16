using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace ServerCertificateChain.Kestrel
{
    /// <summary>
    /// 表示一个服务器证书链，包含一个目标证书和零个或多个中间证书。
    /// </summary>
    [DebuggerDisplay("TargetCertificate: {TargetCertificate.Subject}, IntermediateCertificates: {Count}")]
    sealed class X509Certificate2Chain : X509Certificate2Collection
    {
        private const string PathKey = "Path";
        private const string PasswordKey = "Password";
        private const string CertificateLabel = "CERTIFICATE";

        private readonly ILogger _logger;
        private readonly Lazy<SslStreamCertificateContext> _certificateContext;

        /// <summary>
        /// 获取服务器证书链的目标（叶子）证书。
        /// </summary>
        public X509Certificate2 TargetCertificate { get; }

        /// <summary>
        /// 服务器证书链
        /// </summary>
        /// <param name="targetCertificate">目标（叶子）证书</param>
        /// <param name="intermediateCertificates">中间证书</param>
        /// <param name="logger"></param>
        public X509Certificate2Chain(
            X509Certificate2 targetCertificate,
            X509Certificate2Collection intermediateCertificates,
            ILogger logger) : base(intermediateCertificates)
        {
            this._logger = logger;
            this.TargetCertificate = targetCertificate;
            this._certificateContext = new Lazy<SslStreamCertificateContext>(this.CreateCertificateContext, isThreadSafe: true);
        }

        private SslStreamCertificateContext CreateCertificateContext()
        {
            if (this.Count == 0)
            {
                SslStreamCertificateContext.Create(this.TargetCertificate, null);
            }

            var certificateTrust = SslCertificateTrust.CreateForX509Collection(this);
            var context = SslStreamCertificateContext.Create(this.TargetCertificate, this, false, certificateTrust);
            this.LogCertificateContext(context);
            return context;
        }

        private void LogCertificateContext(SslStreamCertificateContext context)
        {
            var builder = new StringBuilder();

            builder.AppendLine($"{context.TargetCertificate.Subject}, Thumbprint={context.TargetCertificate.Thumbprint}");
            foreach (var item in context.IntermediateCertificates)
            {
                builder.AppendLine($"{item.Subject}, Thumbprint={item.Thumbprint}");
            }

            Log.CustomServerCertificateContextCreated(this._logger, builder.ToString());
        }

        /// <summary>
        /// 获取服务器证书链的 SSL 证书上下文。该上下文会在第一次访问时创建，并且在整个生命周期内保持不变。
        /// </summary>
        /// <returns></returns>
        public SslStreamCertificateContext GetCertificateContext()
        {
            return this._certificateContext.Value;
        }

        /// <summary>
        /// 从配置节中解析服务器证书链。
        /// </summary>
        /// <param name="targetCertificate">目标（叶子）证书</param>
        /// <param name="configurationSection">证书的配置节</param>
        /// <param name="logger"></param>
        /// <returns></returns>
        public static X509Certificate2Chain? ParseFromConfigSection(
            X509Certificate2 targetCertificate,
            IConfigurationSection configurationSection,
            ILogger logger)
        {
            var certPath = configurationSection.GetValue<string>(PathKey);
            if (certPath == null || File.Exists(certPath) == false)
            {
                return null;
            }

            var certBytes = File.ReadAllBytes(certPath);
            if (IsPfxFormat(certBytes))
            {
                var certPassword = configurationSection.GetValue<string>(PasswordKey);
                var collection = new X509Certificate2Collection();
                // 不需要叶子证书，因此可以先加载到内存中，随后再释放。
                collection.Import(certBytes, certPassword, X509KeyStorageFlags.EphemeralKeySet);
                return CreateCertificate2Chain(targetCertificate, collection, logger);
            }

            var certPem = Encoding.UTF8.GetString(certBytes);
            if (PemEncoding.TryFind(certPem, out var pemFields) && certPem[pemFields.Label] == CertificateLabel)
            {
                var collection = new X509Certificate2Collection();
                collection.ImportFromPem(certPem);
                return CreateCertificate2Chain(targetCertificate, collection, logger);
            }

            return null;

            static bool IsPfxFormat(Span<byte> certBytes)
            {
                return certBytes.Length > 1 && certBytes[0] == 0x30 && certBytes[1] >= 0x80;
            }
        }

        private static X509Certificate2Chain? CreateCertificate2Chain(
            X509Certificate2 targetCertificate,
            X509Certificate2Collection collection,
            ILogger logger)
        {
            var leafCert = collection.FirstOrDefault(i => i.Thumbprint == targetCertificate.Thumbprint);
            if (leafCert != null)
            {
                collection.Remove(leafCert);
                leafCert.Dispose();
                return new X509Certificate2Chain(targetCertificate, collection, logger);
            }

            foreach (var cert in collection)
            {
                cert.Dispose();
            }
            return null;
        }
    }
}
