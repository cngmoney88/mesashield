using System.Net;
using MesaShield.Core;
using MesaShield.Core.Ml;
using MesaShield.Core.Net;

namespace MesaShield.Windows;

/// <summary>
/// Drives egress control by polling live TCP connections and running each new external one
/// through the <see cref="EgressGuard"/>. Works for standard users (no elevation needed to
/// *see* connections). When the guard says Block and enforcement is on, it drops the connection
/// via a Windows Firewall rule (that step needs elevation) and raises an alert either way.
/// Reverse-DNS names are cached so the essential-services check can use hostnames when available.
/// </summary>
public sealed class EgressWatcher : IDisposable
{
    private readonly EgressGuard _guard;
    private readonly FirewallManager _firewall;
    private readonly ShieldEventLog _log;
    private readonly CancellationTokenSource _cts = new();
    private readonly HashSet<string> _seen = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, string?> _dnsCache = new(StringComparer.OrdinalIgnoreCase);
    private Task? _loop;

    public bool IsRunning { get; private set; }
    public event Action<EgressDecision>? Decision;

    public EgressWatcher(EgressGuard guard, FirewallManager firewall, ShieldEventLog log)
    {
        _guard = guard;
        _firewall = firewall;
        _log = log;
    }

    public void Start()
    {
        if (IsRunning || !OperatingSystem.IsWindows()) return;
        IsRunning = true;
        _loop = Task.Run(() => LoopAsync(_cts.Token));
        _ = _log.LogAsync("egress", $"Egress monitoring started (mode: {_guard.Mode}).");
    }

    private async Task LoopAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try
            {
                foreach (var conn in ConnectionMonitor.Snapshot(establishedOnly: true))
                {
                    if (conn.Remote is null) continue;
                    var ip = conn.Remote.Address.ToString();
                    var key = $"{conn.ProcessName}|{ip}:{conn.Remote.Port}";
                    if (!_seen.Add(key)) continue;   // only judge each new connection once

                    var obs = new NetworkObservation
                    {
                        ProcessName = conn.ProcessName,
                        RemoteAddress = ip,
                        RemotePort = conn.Remote.Port,
                    };
                    if (!obs.IsExternal) continue;

                    var host = ResolveHost(ip);
                    var decision = _guard.Evaluate(obs, bytesOut: 0, resolvedHost: host);
                    Decision?.Invoke(decision);

                    if (decision.Action == EgressAction.Block)
                        await ActOnBlock(conn.ExecutablePath, ip, decision).ConfigureAwait(false);
                    else if (decision.Action == EgressAction.Watch)
                        await _log.LogAsync("egress", $"Watch: {decision.Reason}", conn.ExecutablePath).ConfigureAwait(false);
                }

                // Cap the "seen" set so it doesn't grow forever.
                if (_seen.Count > 8192) _seen.Clear();

                await Task.Delay(TimeSpan.FromSeconds(3), ct).ConfigureAwait(false);
            }
            catch (OperationCanceledException) { break; }
            catch (Exception ex)
            {
                await _log.LogAsync("error", $"Egress watcher error: {ex.Message}").ConfigureAwait(false);
            }
        }
    }

    private async Task ActOnBlock(string? exePath, string ip, EgressDecision decision)
    {
        await _log.LogAsync("egress", $"BLOCK: {decision.Reason}", exePath).ConfigureAwait(false);
        if (exePath is null) return;
        try
        {
            await _firewall.BlockRemoteForApplicationAsync(exePath, ip, decision.Reason).ConfigureAwait(false);
        }
        catch (UnauthorizedAccessException)
        {
            await _log.LogAsync("egress",
                "Wanted to block this connection but need administrator rights to change the firewall. Run MesaShield as admin for active egress blocking.",
                exePath).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            await _log.LogAsync("error", $"Egress block failed: {ex.Message}").ConfigureAwait(false);
        }
    }

    private string? ResolveHost(string ip)
    {
        if (_dnsCache.TryGetValue(ip, out var cached)) return cached;
        string? host = null;
        try
        {
            // Short timeout so a slow reverse lookup never stalls the loop.
            var task = Task.Run(() => Dns.GetHostEntry(ip).HostName);
            host = task.Wait(TimeSpan.FromMilliseconds(400)) ? task.Result : null;
        }
        catch { host = null; }
        _dnsCache[ip] = host;
        return host;
    }

    public void Dispose()
    {
        _cts.Cancel();
        IsRunning = false;
    }
}
