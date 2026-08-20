using System.Net;
using System.Text.Json;

namespace MesaShield.Core.Ml;

/// <summary>An outbound network connection MesaShield observed.</summary>
public sealed record NetworkObservation
{
    public required string ProcessName { get; init; }
    public required string RemoteAddress { get; init; }
    public int RemotePort { get; init; }

    /// <summary>True if the remote address is a public (internet) address, not LAN/loopback.</summary>
    public bool IsExternal => IsPublic(RemoteAddress);

    internal static bool IsPublic(string address)
    {
        if (!IPAddress.TryParse(address, out var ip)) return false;
        if (IPAddress.IsLoopback(ip)) return false;
        var b = ip.GetAddressBytes();
        if (b.Length == 4)
        {
            if (b[0] == 10) return false;                          // 10.0.0.0/8
            if (b[0] == 172 && b[1] >= 16 && b[1] <= 31) return false; // 172.16.0.0/12
            if (b[0] == 192 && b[1] == 168) return false;          // 192.168.0.0/16
            if (b[0] == 169 && b[1] == 254) return false;          // link-local
            if (b[0] == 127) return false;
            return true;
        }
        // IPv6: treat non-loopback, non-link-local, non-unique-local as public.
        if (ip.IsIPv6LinkLocal) return false;
        if ((b[0] & 0xFE) == 0xFC) return false;                   // fc00::/7 unique local
        return true;
    }
}

/// <summary>
/// Learns which external internet endpoints each program on this machine normally talks to,
/// and flags connections that break the pattern — a program that's never phoned out suddenly
/// reaching an unfamiliar server, which is how data exfiltration and C2 beacons look. Fully
/// on-device; the model is a few KB of decayed counts.
/// </summary>
public sealed class NetworkAnomalyLearner
{
    private readonly FrequencyModel _hosts = new();
    private readonly FrequencyModel _processHost = new();
    private long _observations;

    public long WarmUpObservations { get; init; } = 500;
    public bool IsLearning => _observations < WarmUpObservations;
    public long Observations => _observations;

    public AnomalyAssessment Observe(NetworkObservation obs)
    {
        // Only external connections are interesting for exfil/C2; LAN chatter is ignored.
        if (!obs.IsExternal)
            return new AnomalyAssessment { Score = 0, IsLearning = IsLearning };

        var assessment = Score(obs);

        _hosts.Observe(obs.RemoteAddress);
        _processHost.Observe($"{obs.ProcessName}|{obs.RemoteAddress}");
        _observations++;

        return assessment;
    }

    private AnomalyAssessment Score(NetworkObservation obs)
    {
        if (IsLearning) return new AnomalyAssessment { Score = 0, IsLearning = true };

        var reasons = new List<string>();
        double score = 0;
        var pairKey = $"{obs.ProcessName}|{obs.RemoteAddress}";

        if (!_processHost.HasSeen(pairKey))
        {
            score += 0.35;
            reasons.Add($"{obs.ProcessName} has never connected to {obs.RemoteAddress} before");
        }
        if (!_hosts.HasSeen(obs.RemoteAddress))
        {
            score += 0.25;
            reasons.Add("connecting to an internet address this machine has never contacted");
        }

        // Uncommon ports for outbound traffic are a mild extra signal.
        if (obs.RemotePort is not (80 or 443 or 53 or 123 or 22 or 25 or 587 or 993 or 995))
        {
            score += 0.1;
            reasons.Add($"unusual destination port {obs.RemotePort}");
        }

        return new AnomalyAssessment
        {
            Score = Math.Clamp(score, 0, 1),
            IsLearning = false,
            Reasons = reasons,
        };
    }

    public sealed record State(long Observations, Dictionary<string, double> Hosts, Dictionary<string, double> ProcessHost);

    public void Save(string path)
    {
        var state = new State(_observations, new(_hosts.Snapshot()), new(_processHost.Snapshot()));
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        var tmp = path + ".tmp";
        File.WriteAllText(tmp, JsonSerializer.Serialize(state));
        File.Move(tmp, path, overwrite: true);
    }

    public static NetworkAnomalyLearner Load(string path, long warmUp = 500)
    {
        var learner = new NetworkAnomalyLearner { WarmUpObservations = warmUp };
        try
        {
            if (!File.Exists(path)) return learner;
            var state = JsonSerializer.Deserialize<State>(File.ReadAllText(path));
            if (state is null) return learner;
            learner._observations = state.Observations;
            learner._hosts.Load(state.Hosts);
            learner._processHost.Load(state.ProcessHost);
        }
        catch (Exception ex) when (ex is JsonException or IOException) { }
        return learner;
    }
}
