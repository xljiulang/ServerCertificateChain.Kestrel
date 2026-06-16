## ServerCertificateChain.Kestrel
让 Kestrel 完全使用用户自定义的 ServerCertificateChain 或证书文件的证书链。

### 如何使用

#### 1 NUGET 包
[ServerCertificateChain.Kestrel](https://www.nuget.org/packages/ServerCertificateChain.Kestrel)
 

#### 2 配置 Kestrel
```c#
var builder = WebApplication.CreateBuilder(args);

// 添加此行代码，即可启用 Kestrel 文件证书的证书链功能
builder.WebHost.UseKestrelCustomServerCertificateChain();

builder.WebHost.ConfigureKestrel(k =>
{
    // 你可以在这里添加任意 Kestrel 配置
    // 你的配置代码将在 UseKestrelCustomServerCertificateChain 之前执行
});
```