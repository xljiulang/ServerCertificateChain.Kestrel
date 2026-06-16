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
    sealed class X509Certificate2Chain : X509Certificate2Collection
    {
        private const string PathKey = "Path";
        private const string PasswordKey = "Password";
        private const string CertificateLabel = "CERTIFICATE";

        public X509Certificate2 TargetCertificate { get; }

        public Lazy<SslStreamCertificateContext> CertificateContext { get; }

        public X509Certificate2Chain(
            X509Certificate2 targetCertificate,
            X509Certificate2Collection intermediateCertificates) : base(intermediateCertificates)
        {
            this.TargetCertificate = targetCertificate;
            this.CertificateContext = new Lazy<SslStreamCertificateContext>(this.CreateCertificateContext, isThreadSafe: true);
        }

        private SslStreamCertificateContext CreateCertificateContext()
        {
            var certificateTrust = SslCertificateTrust.CreateForX509Collection(this);
            return SslStreamCertificateContext.Create(this.TargetCertificate, null, false, certificateTrust);
        }

        public static X509Certificate2Chain? ParseFromConfigSection(X509Certificate2 certificate, IConfigurationSection configurationSection)
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
                return CreateCertificate2Chain(certificate, collection);
            }

            var certPem = Encoding.UTF8.GetString(certBytes);
            if (PemEncoding.TryFind(certPem, out var pemFields) && certPem[pemFields.Label] == CertificateLabel)
            {
                var collection = new X509Certificate2Collection();
                collection.ImportFromPem(certPem);
                return CreateCertificate2Chain(certificate, collection);
            }

            return null;

            static bool IsPfxFormat(Span<byte> certBytes)
            {
                return certBytes.Length > 1 && certBytes[0] == 0x30 && certBytes[1] >= 0x80;
            }
        }

        private static X509Certificate2Chain? CreateCertificate2Chain(X509Certificate2 certificate, X509Certificate2Collection collection)
        {
            var leafCert = collection.FirstOrDefault(i => i.Thumbprint == certificate.Thumbprint);
            if (leafCert != null)
            {
                collection.Remove(leafCert);
                leafCert.Dispose();
                return new X509Certificate2Chain(certificate, collection);
            }

            foreach (var cert in collection)
            {
                cert.Dispose();
            }
            return null;
        }
    }
}
