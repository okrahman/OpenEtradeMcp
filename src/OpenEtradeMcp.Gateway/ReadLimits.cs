using OpenEtradeMcp.Contracts;
namespace OpenEtradeMcp.Gateway;
public sealed class TransmissionPolicy : DelegatingHandler
{
    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
    { RequestPolicy.ValidateOutgoing(request); return base.SendAsync(request, ct); }
}
public sealed class ReadLimits(TimeProvider? clock = null)
{
    private readonly object sync = new();
    private readonly TimeProvider time = clock ?? TimeProvider.System;
    private readonly Dictionary<string, Agent> agents = new(StringComparer.Ordinal);
    private int global;
    private sealed class Agent { public Queue<DateTimeOffset> Calls = new(); public int InFlight; }
    public IDisposable? TryAcquire(string id)
    {
        lock (sync)
        {
            var now = time.GetUtcNow();
            if (!agents.TryGetValue(id, out var agent)) agents.Add(id, agent = new());
            while (agent.Calls.TryPeek(out var at) && at <= now.AddMinutes(-1)) agent.Calls.Dequeue();
            if (agent.Calls.Count >= 30 || agent.InFlight >= 2 || global >= 4) return null;
            agent.Calls.Enqueue(now); agent.InFlight++; global++;
            return new Lease(() => { lock (sync) { agent.InFlight--; global--; } });
        }
    }
    private sealed class Lease(Action release) : IDisposable
    {
        private Action? action = release;
        public void Dispose() => Interlocked.Exchange(ref action, null)?.Invoke();
    }
}
