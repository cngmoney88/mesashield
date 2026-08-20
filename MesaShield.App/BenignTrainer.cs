using System.IO;
using MesaShield.Core.Ml;

namespace MesaShield.App;

/// <summary>
/// Trains the one-class "known-good" model from the software already installed on this PC.
/// It walks Program Files and System32, extracts the same static features the scanner uses,
/// and fits the benign profile — entirely locally, no malware samples, nothing uploaded.
/// </summary>
public static class BenignTrainer
{
    public static BenignAnomalyModel.Model? TrainFromThisPc(IProgress<string>? progress = null, int maxFiles = 4000)
    {
        var roots = new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32"),
        }.Where(Directory.Exists).Distinct().ToArray();

        var options = new EnumerationOptions
        {
            RecurseSubdirectories = true,
            IgnoreInaccessible = true,
            AttributesToSkip = FileAttributes.ReparsePoint | FileAttributes.Offline,
        };

        var features = new List<double[]>();
        var scanned = 0;
        foreach (var root in roots)
        {
            IEnumerable<string> files;
            try { files = Directory.EnumerateFiles(root, "*", options); }
            catch { continue; }

            foreach (var file in files)
            {
                if (features.Count >= maxFiles) break;
                var ext = Path.GetExtension(file);
                if (ext is not (".exe" or ".dll" or ".sys")) continue;

                try
                {
                    var info = new FileInfo(file);
                    if (info.Length is < 1024 or > 128 * 1024 * 1024) continue;
                    var headLen = (int)Math.Min(info.Length, 1 * 1024 * 1024);
                    var head = new byte[headLen];
                    using (var stream = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
                        stream.ReadExactly(head, 0, headLen);

                    if (head.Length < 2 || head[0] != (byte)'M' || head[1] != (byte)'Z') continue;
                    features.Add(PeFeatureExtractor.Extract(head, info.Length));

                    if (++scanned % 250 == 0) progress?.Report($"Learning from your software… {scanned} programs analyzed.");
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { /* skip */ }
            }
        }

        if (features.Count < 50) return null;
        progress?.Report($"Fitting the model on {features.Count} known-good programs…");
        return BenignAnomalyModel.Fit(features, $"pc-{features.Count}");
    }
}
