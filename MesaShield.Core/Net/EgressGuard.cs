using System.Text.Json;
using MesaShield.Core.Ml;

namespace MesaShield.Core.Net;

/// <summary>What egress control should do with a connection.</summary>
public enum EgressAction { Allow, Watch, Block }

/// <summary>How aggressively egress control acts.</summary>
public enum EgressMode
{
    /// <summary>Off — no egress decisions.</summary>
    Off,
    /// <summary>Learn what's normal and only alert on the unusual. Nothing is blocked.</summary>
    Observe,
    /// <summary>Block connections to new/unapproved external destinations from non-essential apps.</summary>
    Enforce,
}

/// <summary>A decision about one outbound connection, with a human-readable reason.</summary>
public sealed record EgressDecision
{
    public required EgressAction Action { get; init; }
    public required string Reason { get; init; }
    public required NetworkObservation Observation { get; init; }
    public long BytesOut { get; init; }
    public bool Essential { get; init; }
}

/// <summary>
/// The data-loss-prevention brain. For each outbound connection it combines: is this core OS
/// plumbing (leave it alone), has this program talked to this destination before (learned
/// normal), is it on the user's approved list, and is a large amount of data heading to a
/// brand-new external host (the exfiltration fingerprint). In Enforce mode it returns Block for
/// connections that look like data leaving to somewhere it shouldn't; the Windows layer then
/// drops them via the firewall. Everything is decided on-device.
/// </summary>
public sealed class EgressGuard
{
    private readonly NetworkAnomalyLearner _learner;
    private readonly HashSet<string> _userAllow = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _userBlock = new(StringComparer.OrdinalIgnoreCase);

    public EgressMode Mode { get; set; } = EgressMode.Observe;

    /// <summary>Upload size to a new external host that counts as a strong exfiltration signal.</summary>
    public long LargeUploadBytes { get; set; } = 5 * 1024 * 1024;

    public event Action<EgressDecision>? DecisionMade;

    public EgressGuard(NetworkAnomalyLearner learner) => _learner = learner;

    private static string Key(NetworkObservation o) => $"{o.ProcessName}|{o.RemoteAddress}";

    public void Approve(NetworkObservation o) { _userAllow.Add(Key(o)); _userBlock.Remove(Key(o)); }
    public void Deny(NetworkObservation o) { _userBlock.Add(Key(o)); _userAllow.Remove(Key(o)); }
    public bool IsApproved(NetworkObservation o) => _userAllow.Contains(Key(o));

    /// <summary>Evaluate one outbound connection. <paramref name="resolvedHost"/> is optional (reverse-DNS).</summary>
    public EgressDecision Evaluate(NetworkObservation o, long bytesOut = 0, string? resolvedHost = null)
    {
        var essential = EssentialServices.IsEssential(o.ProcessName, o.RemotePort, resolvedHost);
        EgressDecision Decide(EgressAction action, string reason) =>
            Emit(new EgressDecision { Action = action, Reason = reason, Observation = o, BytesOut = bytesOut, Essential = essential });

        if (Mode == EgressMode.Off) return Decide(EgressAction.Allow, "Egress control off.");
        if (!o.IsExternal) return Decide(EgressAction.Allow, "Local/LAN traffic.");
        if (_userBlock.Contains(Key(o))) return Decide(EgressAction.Block, "You blocked this destination.");
        if (_userAllow.Contains(Key(o))) return Decide(EgressAction.Allow, "You approved this destination.");
        if (essential) return Decide(EgressAction.Allow, "Essential OS/network service.");

        // Feed the learner and see how novel this destination is for this program.
        var assessment = _learner.Observe(o);
        var novel = assessment.Score >= 0.6 || (!assessment.IsLearning && assessment.Reasons.Count > 0);
        var bigUploadToNewHost = bytesOut >= LargeUploadBytes && novel;

        if (assessment.IsLearning)
            return Decide(EgressAction.Allow, "Still learning this machine's normal network behavior.");

        // The genuine data-exfiltration fingerprint: bulk data leaving to a brand-new destination.
        // This is what Enforce blocks — it stops data from actually leaving.
        if (bigUploadToNewHost)
            return Decide(Mode == EgressMode.Enforce ? EgressAction.Block : EgressAction.Watch,
                $"Large upload ({bytesOut / (1024.0 * 1024):F1} MB) to a destination {o.ProcessName} has never used — possible data exfiltration.");

        // A plain connection to a new IP is NOT exfiltration — modern apps (browsers, cloud sync,
        // updates) legitimately hit hundreds of rotating CDN addresses. We watch and log it, but we
        // do not cut it, even in Enforce. Blocking these was blocking normal work (and MesaShield's
        // own updates). Only an explicit user block or the bulk-upload fingerprint above stops traffic.
        if (novel)
            return Decide(EgressAction.Watch,
                $"{o.ProcessName} connecting to an unfamiliar external destination ({o.RemoteAddress}).");

        return Decide(EgressAction.Allow, "Known-normal destination for this program.");
    }

    private EgressDecision Emit(EgressDecision d) { DecisionMade?.Invoke(d); return d; }

    // ---- Persistence of the user's approve/block lists --------------------

    public sealed record State(List<string> Allow, List<string> Block, string Mode, long LargeUploadBytes);

    public void Save(string path)
    {
        var state = new State(_userAllow.ToList(), _userBlock.ToList(), Mode.ToString(), LargeUploadBytes);
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        var tmp = path + ".tmp";
        File.WriteAllText(tmp, JsonSerializer.Serialize(state));
        File.Move(tmp, path, overwrite: true);
    }

    public void Load(string path)
    {
        try
        {
            if (!File.Exists(path)) return;
            var state = JsonSerializer.Deserialize<State>(File.ReadAllText(path));
            if (state is null) return;
            _userAllow.Clear(); foreach (var a in state.Allow) _userAllow.Add(a);
            _userBlock.Clear(); foreach (var b in state.Block) _userBlock.Add(b);
            if (Enum.TryParse<EgressMode>(state.Mode, out var m)) Mode = m;
            if (state.LargeUploadBytes > 0) LargeUploadBytes = state.LargeUploadBytes;
        }
        catch (Exception ex) when (ex is JsonException or IOException) { }
    }
}
