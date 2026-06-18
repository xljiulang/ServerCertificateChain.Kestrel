## ServerCertificateChain.Kestrel
让 Kestrel 完全使用用户自定义的 ServerCertificateChain 或证书文件的证书链。

### 功能介绍
1. 解决任何 pfx 格式的证书文件都不读取证书链的问题。
2. 解决 `Kestrel:Certificates:Default:Path` 证书文件不读取证书链的问题。
3. 避开 kestrel 内部的证书链构建逻辑，完全使用用户代码配置或证书文件的证书链。

### 如何使用
#### 1 NUGET 包
[ServerCertificateChain.Kestrel](https://www.nuget.org/packages/ServerCertificateChain.Kestrel)
 

#### 2 配置 Kestrel
```c#
var builder = WebApplication.CreateBuilder(args);

// 添加此行代码，即可启用 Kestrel 文件证书的证书链功能
// 注意这个行为与 Http3 监听冲突，意味着您不能开启 Http3
builder.WebHost.UseKestrelCustomServerCertificateChain();

builder.WebHost.ConfigureKestrel(k =>
{
    // 你可以在这里添加任意 Kestrel 配置
    // 你的配置代码将在 UseKestrelCustomServerCertificateChain 之前执行
});
```
现在，你完全可以使用 acme.sh/win-acme 等工具申请的证书文件安装到对应 `Kestrel:Certificates:Default` 的值，不用担心证书链的问题了。
```json
{
  "Kestrel": {
    "Endpoints": {
      "Https": {
        "Url": "http://*:80"       
      },
      "Https": {
        "Url": "https://*:443"       
      }
    },
    "Certificates": {
      "Default": {
        "Path": "zerossl/your_domain.crt",
        "KeyPath": "zerossl/your_domain.key"
      }
    }
  }
}
```
