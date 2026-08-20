using System.Text.Json;
using System.Text.Json.Serialization;

namespace MesaShield.Core.Ml;

/// <summary>
/// A one-class ("known-good") model. Instead of learning what malware looks like — which needs
/// a corpus of real malware — it learns the statistical profile of legitimate software from
/// clean files, then measures how far a new file sits from that profile (a standardized
/// Euclidean / diagonal-Mahalanobis distance). Files that don't resemble normal software are
/// flagged as unfamiliar. This is safe to train (no malware samples needed), runs offline, and
/// is deliberately conservative: it only ever raises "suspicious," never auto-quarantines.
/// </summary>
public sealed class BenignAnomalyModel
{
    public sealed record Model
    {
        [JsonPropertyName("version")] public string Version { get; init; } = "0";
        [JsonPropertyName("featureNames")] public string[] FeatureNames { get; init; } = Array.Empty<string>();
        [JsonPropertyName("mean")] public double[] Mean { get; init; } = Array.Empty<double>();
        [JsonPropertyName("std")] public double[] Std { get; init; } = Array.Empty<double>();
        /// <summary>Distance at/above which a file is treated as unfamiliar (suspicious).</summary>
        [JsonPropertyName("suspiciousDistance")] public double SuspiciousDistance { get; init; } = 4.0;
    }

    private readonly Model _model;
    public string Version => _model.Version;
    public bool IsUsable => _model.Mean.Length > 0 && _model.Mean.Length == _model.Std.Length;

    private BenignAnomalyModel(Model model) => _model = model;

    public static BenignAnomalyModel FromModel(Model model) => new(model);

    public static BenignAnomalyModel? Load(string path)
    {
        try
        {
            if (!File.Exists(path)) return null;
            var model = JsonSerializer.Deserialize<Model>(File.ReadAllText(path));
            return model is null ? null : new BenignAnomalyModel(model);
        }
        catch (Exception ex) when (ex is JsonException or IOException) { return null; }
    }

    /// <summary>Standardized distance of a feature vector from the known-good centroid.</summary>
    public double Distance(double[] features)
    {
        if (!IsUsable || features.Length != _model.Mean.Length) return 0;
        double sumSq = 0;
        for (var i = 0; i < features.Length; i++)
        {
            var std = _model.Std[i] > 1e-9 ? _model.Std[i] : 1.0;
            var z = (features[i] - _model.Mean[i]) / std;
            sumSq += z * z;
        }
        return Math.Sqrt(sumSq / features.Length); // RMS z-score, scale-stable across feature counts
    }

    /// <summary>Returns a Suspicious verdict with the distance when a PE file doesn't resemble known-good software.</summary>
    public (ThreatSeverity Severity, double Distance)? Classify(ReadOnlySpan<byte> head, long fileLength)
    {
        var features = PeFeatureExtractor.Extract(head, fileLength);
        var distance = Distance(features);
        return distance >= _model.SuspiciousDistance ? (ThreatSeverity.Suspicious, distance) : null;
    }

    /// <summary>Fit a model from feature vectors of known-good files (used by tests / an in-app trainer).</summary>
    public static Model Fit(IReadOnlyList<double[]> benignFeatures, string version, double stdMultiplier = 4.0)
    {
        if (benignFeatures.Count == 0) throw new ArgumentException("No benign samples.");
        var n = benignFeatures[0].Length;
        var mean = new double[n];
        var std = new double[n];
        foreach (var f in benignFeatures)
            for (var i = 0; i < n; i++) mean[i] += f[i];
        for (var i = 0; i < n; i++) mean[i] /= benignFeatures.Count;
        foreach (var f in benignFeatures)
            for (var i = 0; i < n; i++) { var d = f[i] - mean[i]; std[i] += d * d; }
        for (var i = 0; i < n; i++) std[i] = Math.Sqrt(std[i] / Math.Max(benignFeatures.Count - 1, 1));

        // Threshold: the RMS distance that covers the bulk of benign files, times a margin.
        var model = new Model { Version = version, FeatureNames = PeFeatureExtractor.FeatureNames, Mean = mean, Std = std, SuspiciousDistance = stdMultiplier };
        var scorer = new BenignAnomalyModel(model);
        var distances = benignFeatures.Select(scorer.Distance).OrderBy(d => d).ToList();
        var p99 = distances[(int)(distances.Count * 0.99).Clamp(0, distances.Count - 1)];
        return model with { SuspiciousDistance = Math.Max(p99 * 1.5, 3.0) };
    }
}

internal static class MathExtensions
{
    public static double Clamp(this double v, double min, double max) => Math.Clamp(v, min, max);
}
