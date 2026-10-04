using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;

namespace OpenEtradeMcp.Contracts;

public sealed class Assertions(RSA key, string issuer, TimeProvider? clock = null)
{
    public const string Audience = "etrade-read-gateway";
    public const string Type = "etrade-request+jwt";
    private readonly TimeProvider time = clock ?? TimeProvider.System;
    public string Issue(TokenStatus status, ReadRequest request)
    {
        RequestPolicy.Validate(request);
        var now = time.GetUtcNow().UtcDateTime;
        var claims = new[] { new Claim("agent", status.AgentId), new Claim("grant", status.GrantId),
            new Claim("client", status.ClientId), new Claim("origin", status.TokenId), new Claim("op", request.Operation.ToString()),
            new Claim("digest", request.Digest()), new Claim(JwtRegisteredClaimNames.Jti, Convert.ToHexString(RandomNumberGenerator.GetBytes(32))) };
        var token = new JwtSecurityToken(issuer, Audience, claims, now, now.AddSeconds(10), new(new RsaSecurityKey(key), SecurityAlgorithms.RsaSha256));
        token.Header["typ"] = Type;
        token.Payload["iat"] = new DateTimeOffset(now).ToUnixTimeSeconds();
        return new JwtSecurityTokenHandler().WriteToken(token);
    }
    public ClaimsPrincipal Verify(string token, ReadRequest? request = null)
    {
        if (token.Length > 8192) throw new PolicyException();
        var handler = new JwtSecurityTokenHandler { MapInboundClaims = false };
        var principal = handler.ValidateToken(token, new TokenValidationParameters {
            ValidateIssuer = true, ValidIssuer = issuer, ValidateAudience = true, ValidAudience = Audience,
            ValidateIssuerSigningKey = true, IssuerSigningKey = new RsaSecurityKey(key),
            ValidAlgorithms = [SecurityAlgorithms.RsaSha256], ValidTypes = [Type], RequireExpirationTime = true,
            ClockSkew = TimeSpan.Zero, LifetimeValidator = (nbf, exp, _, _) => nbf.HasValue && exp.HasValue &&
                nbf <= time.GetUtcNow().UtcDateTime && exp > time.GetUtcNow().UtcDateTime && exp - nbf <= TimeSpan.FromSeconds(10)
        }, out _);
        foreach (var name in new[] { "agent", "grant", "client", "origin", "op", "digest", "jti", "exp", "iat" })
            if (principal.FindAll(name).Count() != 1) throw new PolicyException();
        if (!Enum.TryParse<ReadOperation>(principal.FindFirstValue("op"), out var operation) || !Enum.IsDefined(operation)) throw new PolicyException();
        if (request != null && (request.Operation != operation || request.Digest() != principal.FindFirstValue("digest"))) throw new PolicyException();
        return principal;
    }
}
