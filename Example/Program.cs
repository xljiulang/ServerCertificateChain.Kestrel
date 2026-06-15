namespace Example
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder(args);

            // 添加此行代码，即可启用 Kestrel 文件证书的证书链功能
            builder.WebHost.UseKestrelCustomServerCertificateChain();

            builder.WebHost.ConfigureKestrel(k =>
            {
                // 你可以在这里添加任意 Kestrel 配置
                // 你的配置代码将在 UseKestrelCustomServerCertificateChain 之前执行
            });

            var app = builder.Build();
            app.MapGet("/", context => context.Response.WriteAsync("ServerCertificateChain.Kestrel"));

            app.Run();
        }
    }
}
