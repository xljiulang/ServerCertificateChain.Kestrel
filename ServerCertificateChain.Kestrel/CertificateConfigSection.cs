using Microsoft.Extensions.Configuration;
using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace ServerCertificateChain.Kestrel
{

    /// <summary>
    /// 证书与配置节。
    /// </summary>
    sealed class CertificateConfigSection(X509Certificate2 certificate, IConfigurationSection configSection) : IEquatable<CertificateConfigSection>
    {
        private const string PathKey = "Path";
        private const string PasswordKey = "Password";
        private const string CertificateLabel = "CERTIFICATE";

        public X509Certificate2 Certificate { get; } = certificate;

        public IConfigurationSection ConfigSection { get; } = configSection;

        public override int GetHashCode()
        {
            return HashCode.Combine(this.Certificate, this.ConfigSection.Path);
        }

        public override bool Equals(object? obj)
        {
            return obj is CertificateConfigSection other && this.Equals(other);
        }

        public bool Equals(CertificateConfigSection? other)
        {
            return other != null && other.ConfigSection.Path == this.ConfigSection.Path && other.Certificate == this.Certificate;
        }

        /// <summary>
        /// 从证书文件加载证书链。支持 PFX 和 PEM 格式。
        /// </summary>
        /// <returns></returns>
        public X509Certificate2Collection? LoadCertificateChain()
        {
            var configSession = this.ConfigSection;
            var certificate = this.Certificate;

            var certPath = configSession.GetValue<string>(PathKey);
            if (certPath == null || File.Exists(certPath) == false)
            {
                return null;
            }

            var certBytes = File.ReadAllBytes(certPath);
            if (IsPfxFormat(certBytes))
            {
                var certPassword = configSession.GetValue<string>(PasswordKey);
#if NET9_0_OR_GREATER
                var collection = X509CertificateLoader.LoadPkcs12Collection(certBytes, certPassword);
#else
                var collection = new X509Certificate2Collection();
                // 不需要叶子证书，因此可以先加载到内存中，随后再释放。
                collection.Import(certBytes, certPassword, X509KeyStorageFlags.EphemeralKeySet);
#endif
                return MakeCertificateChain(collection, certificate);
            }

            var certPem = Encoding.UTF8.GetString(certBytes);
            if (PemEncoding.TryFind(certPem, out var pemFields) && certPem[pemFields.Label] == CertificateLabel)
            {
                var collection = new X509Certificate2Collection();
                collection.ImportFromPem(certPem);
                return MakeCertificateChain(collection, certificate);
            }

            return null;
        }

        private static bool IsPfxFormat(Span<byte> certBytes)
        {
            return certBytes.Length > 1 && certBytes[0] == 0x30 && certBytes[1] >= 0x80;
        }

        private static X509Certificate2Collection? MakeCertificateChain(X509Certificate2Collection collection, X509Certificate2 certificate)
        {
            var leafCert = collection.FirstOrDefault(i => i.Thumbprint == certificate.Thumbprint);
            if (leafCert != null)
            {
                collection.Remove(leafCert);
                leafCert.Dispose();
                return collection.Count > 0 ? collection : null;
            }

            foreach (var cert in collection)
            {
                cert.Dispose();
            }
            return null;
        }
    }
}