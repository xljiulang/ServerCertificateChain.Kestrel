using Microsoft.Extensions.Configuration;
using System;
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
    sealed class X509Certificate2Chain : X509Certificate2Collection
    {
        private const string PathKey = "Path";
        private const string PasswordKey = "Password";
        private const string CertificateLabel = "CERTIFICATE";

        /// <summary>
        /// 获取服务器证书链的目标（叶子）证书。
        /// </summary>
        public X509Certificate2 TargetCertificate { get; }

        /// <summary>
        /// 获取服务器证书链的 SSL 证书上下文。该上下文会在第一次访问时创建，并且在整个生命周期内保持不变。
        /// </summary>
        public Lazy<SslStreamCertificateContext> CertificateContext { get; }

        /// <summary>
        /// 服务器证书链
        /// </summary>
        /// <param name="targetCertificate">目标（叶子）证书</param>
        /// <param name="intermediateCertificates">中间证书</param>
        public X509Certificate2Chain(
            X509Certificate2 targetCertificate,
            X509Certificate2Collection intermediateCertificates) : base(intermediateCertificates)
        {
            this.TargetCertificate = targetCertificate;
            this.CertificateContext = new Lazy<SslStreamCertificateContext>(this.CreateCertificateContext, isThreadSafe: true);
        }

        private SslStreamCertificateContext CreateCertificateContext()
        {
            if (this.Count == 0)
            {
                SslStreamCertificateContext.Create(this.TargetCertificate, null);
            }

            var certificateTrust = SslCertificateTrust.CreateForX509Collection(this);
            return SslStreamCertificateContext.Create(this.TargetCertificate, this, false, certificateTrust);
        }

        /// <summary>
        /// 从配置节中解析服务器证书链。
        /// </summary>
        /// <param name="targetCertificate">目标（叶子）证书</param>
        /// <param name="configurationSection">证书的配置节</param>
        /// <returns></returns>
        public static X509Certificate2Chain? ParseFromConfigSection(X509Certificate2 targetCertificate, IConfigurationSection configurationSection)
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
                return CreateCertificate2Chain(targetCertificate, collection);
            }

            var certPem = Encoding.UTF8.GetString(certBytes);
            if (PemEncoding.TryFind(certPem, out var pemFields) && certPem[pemFields.Label] == CertificateLabel)
            {
                var collection = new X509Certificate2Collection();
                collection.ImportFromPem(certPem);
                return CreateCertificate2Chain(targetCertificate, collection);
            }

            return null;

            static bool IsPfxFormat(Span<byte> certBytes)
            {
                return certBytes.Length > 1 && certBytes[0] == 0x30 && certBytes[1] >= 0x80;
            }
        }

        private static X509Certificate2Chain? CreateCertificate2Chain(X509Certificate2 targetCertificate, X509Certificate2Collection collection)
        {
            var leafCert = collection.FirstOrDefault(i => i.Thumbprint == targetCertificate.Thumbprint);
            if (leafCert != null)
            {
                collection.Remove(leafCert);
                leafCert.Dispose();
                return new X509Certificate2Chain(targetCertificate, collection);
            }

            foreach (var cert in collection)
            {
                cert.Dispose();
            }
            return null;
        }
    }
}
