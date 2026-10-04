using OpenEtradeMcp.Contracts;
namespace OpenEtradeMcp.Gateway;
public sealed class AuthorizationWatch(EtradeOAuth1AuthenticationHandler auth) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken ct)
    {
        var needsAuthorization = false;
        using var timer = new PeriodicTimer(TimeSpan.FromMinutes(1));
        do
        {
            try
            {
                await auth.RefreshStatusAsync();
                var needed = !auth.IsAuthenticated;
                if (needed && !needsAuthorization) SecurityEvent.Write("reauthorization_required");
                needsAuthorization = needed;
            }
            catch (Exception) { SecurityEvent.Write("service_unavailable"); }
        } while (await timer.WaitForNextTickAsync(ct));
    }
}
