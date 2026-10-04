using Microsoft.AspNetCore.Hosting;
using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Server.Kestrel.Https;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace OpenEtradeMcp.Contracts;

// Pin the CA AND the expected leaf identity. No forwarded certificate headers are trusted.
public static class InternalTls
{
    public static string Required(this IConfiguration config, string key) => config[key] is { Length: > 0 } v ? v : throw new InvalidOperationException("Missing configuration: " + key);
    public static X509Certificate2 Certificate(IConfiguration config) => X509CertificateLoader.LoadPkcs12FromFile(config.Required("Tls:Certificate"), null);
    public static bool Trust(X509Certificate2? cert, X509Certificate2 ca, string identity)
    {
        if (cert == null || cert.GetNameInfo(X509NameType.DnsName, false) != identity) return false;
        using var chain = new X509Chain();
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.CustomTrustStore.Add(ca);
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        chain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;
        return chain.Build(cert);
    }
    public static void Listen(WebApplicationBuilder builder, bool requireClient = true)
    {
        var config = builder.Configuration;
        var cert = Certificate(config);
        var ca = X509CertificateLoader.LoadCertificateFromFile(config.Required("Tls:Ca"));
        builder.WebHost.ConfigureKestrel(k => {
            k.Limits.MaxRequestBodySize = 32768;
            k.ListenAnyIP(8443, l => l.UseHttps(new HttpsConnectionAdapterOptions {
                ServerCertificate = cert, ClientCertificateMode = ClientCertificateMode.RequireCertificate,
                ClientCertificateValidation = (c, _, _) => new[] { "ingress", "mcp", "authorization", "gateway" }.Any(id => Trust(c, ca, id))
            }));
        });
    }
    public static HttpClient Client(IConfiguration config, string identity, string urlKey)
    {
        var ca = X509CertificateLoader.LoadCertificateFromFile(config.Required("Tls:Ca"));
        var handler = new HttpClientHandler { AllowAutoRedirect = false, UseProxy = false };
        handler.ClientCertificates.Add(Certificate(config));
        handler.ServerCertificateCustomValidationCallback = (_, cert, _, errors) =>
            (errors & SslPolicyErrors.RemoteCertificateNameMismatch) == 0 && Trust(cert, ca, identity);
        var uri = new Uri(config.Required(urlKey));
        if (uri.Scheme != "https" || uri.UserInfo != "" || uri.Query != "" || uri.Fragment != "") throw new InvalidOperationException("HTTPS internal URL required.");
        return new HttpClient(handler) { BaseAddress = uri, Timeout = TimeSpan.FromSeconds(15) };
    }
    public static string Peer(HttpContext ctx) => ctx.Connection.ClientCertificate?.GetNameInfo(X509NameType.DnsName, false) ?? "";
    public static bool Allowed(HttpContext ctx, params string[] peers) => peers.Contains(Peer(ctx), StringComparer.Ordinal);
    public static void SafeErrors(WebApplication app)
    {
        app.Use(async (ctx, next) => {
            try { await next(ctx); }
            catch (Exception) when (!ctx.Response.HasStarted) {
                SecurityEvent.Write("service_unavailable");
                ctx.Response.StatusCode = 503;
                await ctx.Response.WriteAsJsonAsync(new { error = "authorization_or_service_unavailable" });
            }
        });
    }
}

public static class SecurityEvent
{
    public static void Write(string action) => Console.WriteLine(System.Text.Json.JsonSerializer.Serialize(new { action }));
}
