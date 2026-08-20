using System.Text.Json;

namespace MesaShield.Core.Ml;

/// <summary>One thing MesaShield observed happening on the machine (a process launch).</summary>
public sealed record ProcessObservation
{
    public required string ExecutablePath { get; init; }
    public required int HourOfDay { get; init; }           // 0-23, local time
    public bool? IsSigned { get; init; }
    public string? ParentPath { get; init; }
    public string? Sha256 { get; init; }

    /// <summary>Coarse location bucket derived from the path (system / programfiles / user / temp / other).</summary>
    public string LocationBucket => Bucket(ExecutablePath);

    internal static string Bucket(string path)
    {
        var p = path.Replace('/', '\\').ToLowerInvariant();
        if (p.Contains("\\windows\\")) return "system";
        if (p.Contains("\\program files")) return "programfiles";
        if (p.Contains("\\appdata\\local\\temp\\") || p.Contains("\\temp\\") || p.Contains("\\tmp\\")) return "temp";
        if (p.Contains("\\downloads\\")) return "downloads";
        if (p.Contains("\\appdata\\")) return "appdata";
        if (p.Contains("\\users\\")) return "user";
        return "other";
    }
}

/// <summary>The learner's verdict on one observation, with human-readable reasons.</summary>
public sealed record AnomalyAssessment
{
    public required double Score { get; init; }          // 0 (normal) .. 1 (very anomalous)
    public required bool IsLearning { get; init; }       // still in warm-up; not yet alerting
    public IReadOnlyList<string> Reasons { get; init; } = Array.Empty<string>();

    public ThreatSeverity? SuggestedSeverity => Score switch
    {
        >= 0.85 => ThreatSeverity.Malicious,
        >= 0.6 => ThreatSeverity.Suspicious,
        _ => null,
    };
}

/// <summary>
/// A fully on-device, privacy-preserving anomaly detector. It learns what's normal for THIS
/// machine — which programs run, from where, signed or not, at what hours — and scores each new
/// event for how surprising it is. Nothing leaves the device; the model is a few KB of counts
/// and running statistics. It stays quiet during a warm-up period so it doesn't cry wolf while
/// still learning, then flags genuine outliers with explanations.
/// </summary>
public sealed class AnomalyLearner
{
    private readonly FrequencyModel _exePaths = new();
    private readonly FrequencyModel _locations = new();
    private readonly FrequencyModel _parents = new();
    private OnlineStat _hour = new() { Decay = 0.9995 };
    private long _observations;

    /// <summary>Observations required before the learner starts scoring (warm-up). Default 300.</summary>
    public long WarmUpObservations { get; init; } = 300;

    public bool IsLearning => _observations < WarmUpObservations;
    public long Observations => _observations;

    /// <summary>Update the model with an observation and return how anomalous it was.</summary>
    public AnomalyAssessment Observe(ProcessObservation obs)
    {
        var assessment = Score(obs);

        // Learn from it (even anomalies — the model tracks reality; detection layers act on threats).
        _exePaths.Observe(obs.ExecutablePath);
        _locations.Observe(obs.LocationBucket);
        if (obs.ParentPath is not null) _parents.Observe(obs.ParentPath);
        _hour.Add(obs.HourOfDay);
        _observations++;

        return assessment;
    }

    private AnomalyAssessment Score(ProcessObservation obs)
    {
        var reasons = new List<string>();
        double score = 0;

        // Novelty of the executable itself — the strongest signal.
        var exeNovel = !_exePaths.HasSeen(obs.ExecutablePath);
        if (exeNovel)
        {
            score += 0.45;
            reasons.Add("first time this program has run on this machine");
        }

        // Running from an unusual location for this machine (e.g. temp, when programs normally come from Program Files).
        var locProb = _locations.Probability(obs.LocationBucket);
        if (!_locations.HasSeen(obs.LocationBucket))
        {
            score += 0.2;
            reasons.Add($"launched from an unusual location ({obs.LocationBucket})");
        }
        else if (locProb < 0.05 && obs.LocationBucket is "temp" or "downloads" or "appdata")
        {
            score += 0.15;
            reasons.Add($"rarely-used, higher-risk location ({obs.LocationBucket})");
        }

        // Unsigned executables from user-writable locations are riskier.
        if (obs.IsSigned == false && obs.LocationBucket is "temp" or "downloads" or "user" or "appdata")
        {
            score += 0.2;
            reasons.Add("unsigned program from a user-writable folder");
        }

        // Unusual hour for this machine (only meaningful once we have a stable baseline).
        if (_hour.Count > 50)
        {
            var z = _hour.ZScore(obs.HourOfDay);
            if (z > 3)
            {
                score += 0.1;
                reasons.Add($"running at an unusual time for this machine ({obs.HourOfDay}:00)");
            }
        }

        // Unusual parent process (e.g. Office spawning a script host).
        if (obs.ParentPath is not null && _parents.TotalObservations > 50 && !_parents.HasSeen(obs.ParentPath))
        {
            score += 0.1;
            reasons.Add("started by an unfamiliar parent program");
        }

        return new AnomalyAssessment
        {
            Score = Math.Clamp(score, 0, 1),
            IsLearning = IsLearning,
            Reasons = reasons,
        };
    }

    // ---- Persistence ------------------------------------------------------

    public sealed record State(
        long Observations,
        Dictionary<string, double> ExePaths,
        Dictionary<string, double> Locations,
        Dictionary<string, double> Parents,
        long HourCount, double HourMean, double HourM2);

    public void Save(string path)
    {
        var (hc, hm, hm2) = _hour.Snapshot();
        var state = new State(_observations,
            new(_exePaths.Snapshot()), new(_locations.Snapshot()), new(_parents.Snapshot()),
            hc, hm, hm2);
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        var tmp = path + ".tmp";
        File.WriteAllText(tmp, JsonSerializer.Serialize(state));
        File.Move(tmp, path, overwrite: true);
    }

    public static AnomalyLearner Load(string path, long warmUp = 300)
    {
        var learner = new AnomalyLearner { WarmUpObservations = warmUp };
        try
        {
            if (!File.Exists(path)) return learner;
            var state = JsonSerializer.Deserialize<State>(File.ReadAllText(path));
            if (state is null) return learner;
            learner._observations = state.Observations;
            learner._exePaths.Load(state.ExePaths);
            learner._locations.Load(state.Locations);
            learner._parents.Load(state.Parents);
            learner._hour = OnlineStat.FromSnapshot(state.HourCount, state.HourMean, state.HourM2, 0.9995);
        }
        catch (Exception ex) when (ex is JsonException or IOException)
        {
            // Corrupt model → start fresh.
        }
        return learner;
    }
}
