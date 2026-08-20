namespace MesaShield.Core.Ml;

/// <summary>
/// A decayed frequency table over categorical values (e.g. executable paths, remote ports,
/// parent processes). It answers two questions the anomaly learner needs: "have we ever
/// seen this before?" (novelty) and "how rare is it?" (probability). Old observations fade
/// so the model tracks the machine's current normal rather than its whole history.
/// </summary>
public sealed class FrequencyModel
{
    private readonly Dictionary<string, double> _counts = new(StringComparer.OrdinalIgnoreCase);
    private double _total;

    /// <summary>Per-observation decay applied to all counts. 1 = never forget.</summary>
    public double Decay { get; init; } = 0.9995;

    public int DistinctValues => _counts.Count;
    public double TotalObservations => _total;

    public void Observe(string value)
    {
        if (Decay < 1.0)
        {
            // Fade everything slightly, then credit the observed value.
            var keys = _counts.Keys.ToList();
            foreach (var k in keys)
            {
                _counts[k] *= Decay;
                if (_counts[k] < 1e-4) _counts.Remove(k);
            }
            _total *= Decay;
        }
        _counts[value] = (_counts.TryGetValue(value, out var c) ? c : 0) + 1;
        _total += 1;
    }

    public bool HasSeen(string value) => _counts.ContainsKey(value);

    /// <summary>Laplace-smoothed probability of this value. Unseen values get a small non-zero prob.</summary>
    public double Probability(string value)
    {
        var count = _counts.TryGetValue(value, out var c) ? c : 0;
        return (count + 1) / (_total + DistinctValues + 1);
    }

    /// <summary>Novelty in [0,1]: 1 for never-seen, approaching 0 for very common values.</summary>
    public double Novelty(string value)
    {
        if (!HasSeen(value)) return 1.0;
        // Frequent value → low novelty. Uses the value's share of observations.
        var share = _counts[value] / Math.Max(_total, 1);
        return Math.Clamp(1.0 - share, 0.0, 1.0);
    }

    public IReadOnlyDictionary<string, double> Snapshot() => _counts;

    public void Load(IDictionary<string, double> counts)
    {
        _counts.Clear();
        _total = 0;
        foreach (var (k, v) in counts) { _counts[k] = v; _total += v; }
    }
}
