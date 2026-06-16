using Microsoft.Extensions.Logging;

namespace Microsoft.AspNetCore.Hosting
{
    static partial class Log
    {
        [LoggerMessage(Level = LogLevel.Information, Message = "Successfully loaded the server certificate chain from '{endpointPath}' for '{serverCertificateSubject}'.")]
        public static partial void ServerCertificateChainLoaded(ILogger logger, string serverCertificateSubject, string endpointPath);

        [LoggerMessage(Level = LogLevel.Warning, Message = "Failed to load the server certificate chain from '{endpointPath}' for '{serverCertificateSubject}'.")]
        public static partial void ServerCertificateChainLoadFailed(ILogger logger, string serverCertificateSubject, string endpointPath);

        [LoggerMessage(Level = LogLevel.Information, Message = "Successfully created a custom certificate context '{certificateContext}")]
        public static partial void CustomServerCertificateContextCreated(ILogger logger, string certificateContext);
    }
}