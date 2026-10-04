using System.Net;
using System.Net.Http.Json;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Configuration;
namespace OpenEtradeMcp.Contracts;

public static class BrokerageTransport
{
    public static SocketsHttpHandler Create(IConfiguration config)
    {
        var proxy = new Uri(config.Required("BrokerageProxy"));
        if (proxy.Scheme != "http" || proxy.Host != "brokerage-proxy" || proxy.Port != 3128) throw new PolicyException();
        var ca = X509CertificateLoader.LoadCertificateFromFile(config.Required("Tls:Ca"));
        var cert = InternalTls.Certificate(config);
        return new SocketsHttpHandler {
            AllowAutoRedirect = false, UseProxy = true, Proxy = new WebProxy(proxy),
            ConnectCallback = async (context, ct) => {
                if (context.DnsEndPoint.Host != proxy.Host || context.DnsEndPoint.Port != proxy.Port) throw new PolicyException();
                var socket = new Socket(SocketType.Stream, ProtocolType.Tcp);
                try {
                    await socket.ConnectAsync(context.DnsEndPoint, ct);
                    var stream = new SslStream(new NetworkStream(socket, ownsSocket: true), false,
                        (_, remote, _, errors) => remote is X509Certificate2 c &&
                            (errors & SslPolicyErrors.RemoteCertificateNameMismatch) == 0 && InternalTls.Trust(c, ca, "brokerage-proxy"));
                    await stream.AuthenticateAsClientAsync(new SslClientAuthenticationOptions {
                        TargetHost = "brokerage-proxy", ClientCertificates = new X509CertificateCollection { cert },
                        EnabledSslProtocols = System.Security.Authentication.SslProtocols.Tls12 | System.Security.Authentication.SslProtocols.Tls13
                    }, ct);
                    return stream;
                } catch { socket.Dispose(); throw; }
            }
        };
    }
}
public sealed record IdentityFetchRequest(string Url, string Method, string? Bearer, string? Form);
public sealed record IdentityFetchReply(int Status, string Body);
// Backchannel requests are typed and sent to the mTLS identity fetch service, which independently
// enforces exact URL/method/header destinations. It has no API to fetch arbitrary internet content.
public sealed class RestrictedIdentityHandler(IConfiguration config) : HttpMessageHandler
{
    private readonly HttpClient proxy = InternalTls.Client(config, "identity-proxy", "IdentityFetchUrl");
    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage message, CancellationToken ct)
    {
        var uri = message.RequestUri ?? throw new PolicyException();
        if (uri.Scheme != "https" || !uri.IsDefaultPort || uri.UserInfo != "" || uri.Fragment != "") throw new PolicyException();
        var body = message.Content == null ? null : await message.Content.ReadAsStringAsync(ct);
        var auth = message.Headers.Authorization;
        if (auth != null && auth.Scheme != "Bearer") throw new PolicyException();
        var fetch = new IdentityFetchRequest(uri.AbsoluteUri, message.Method.Method, auth?.Parameter, body);
        using var content = new StringContent(System.Text.Json.JsonSerializer.Serialize(fetch, StrictJson.Options), System.Text.Encoding.UTF8, "application/json");
        using var response = await proxy.PostAsync("/fetch", content, ct);
        if (!response.IsSuccessStatusCode) throw new PolicyException();
        var value = await response.Content.ReadFromJsonAsync<IdentityFetchReply>(ct) ?? throw new PolicyException();
        return new HttpResponseMessage((HttpStatusCode)value.Status) { Content = new StringContent(value.Body, System.Text.Encoding.UTF8, "application/json") };
    }
    protected override void Dispose(bool disposing) { if (disposing) proxy.Dispose(); base.Dispose(disposing); }
}
