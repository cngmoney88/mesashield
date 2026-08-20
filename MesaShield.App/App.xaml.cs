using System.Diagnostics;
using System.IO;
using System.Net.Http;
using System.Reflection;
using System.Windows;
using MesaShield.Core;
using MesaShield.Core.Ml;
using MesaShield.Windows;

namespace MesaShield.App;

public partial class App : System.Windows.Application
{
    /// <summary>All MesaShield state lives under %LocalAppData%\MesaShield.</summary>
    public static string DataDirectory { get; } = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "MesaShield");

    public static string SignaturesDirectory => Path.Combine(DataDirectory, "Signatures");
    public static string RulesDirectory => Path.Combine(DataDirectory, "Rules");
    public static string QuarantineDirectory => Path.Combine(DataDirectory, "Quarantine");
    public static string LogsDirectory => Path.Combine(DataDirectory, "Logs");
    public static string SettingsPath => Path.Combine(DataDirectory, "settings.json");
    public static string ReputationCachePath => Path.Combine(DataDirectory, "reputation-cache.json");

    public static SemVer CurrentVersion { get; } = ResolveVersion();

    public static AppSettings Settings { get; private set; } = null!;
    public static SignatureDatabase Signatures { get; } = new();
    public static PatternScanner Patterns { get; } = new();
    public static ScanEngine Engine { get; private set; } = null!;
    public static QuarantineManager Quarantine { get; private set; } = null!;
    public static ShieldEventLog EventLog { get; private set; } = null!;
    public static SignatureUpdater Updater { get; private set; } = null!;
    public static UpdateChecker AppUpdater { get; private set; } = null!;
    public static ReputationClient Reputation { get; private set; } = null!;
    public static RealTimeProtector RealTime { get; private set; } = null!;
    public static ProcessWatcher ProcessWatch { get; private set; } = null!;
    public static UsbWatcher Usb { get; private set; } = null!;
    public static FirewallManager Firewall { get; private set; } = null!;
    public static AmsiScanner Amsi { get; private set; } = null!;
    public static BehaviorEngine Behavior { get; } = new();
    public static BehaviorMonitor BehaviorWatch { get; private set; } = null!;
    public static JobScheduler Scheduler { get; private set; } = null!;
    public static AnomalyLearner Learner { get; private set; } = null!;
    public static NetworkAnomalyLearner NetworkLearner { get; private set; } = null!;
    public static MalwareClassifier? Classifier { get; private set; }
    public static EtwMonitor Etw { get; private set; } = null!;
    public static FleetReporter Fleet { get; private set; } = null!;
    public static long ThreatsHandledTotal;

    public static string StatusPathLocal => Path.Combine(DataDirectory, "status.json");
    public static string NetworkModelPath => Path.Combine(DataDirectory, "Models", "network.json");

    public static string AnomalyModelPath => Path.Combine(DataDirectory, "Models", "anomaly.json");
    public static string ClassifierModelPath => Path.Combine(DataDirectory, "Models", "classifier.json");

    public static bool StartMinimized { get; private set; }
    private static int _learnerObservationsSinceSave;
    private static System.Threading.Timer? _fleetTimer;

    private static MachineStatus BuildMachineStatus()
    {
        int quarantined = 0;
        try { quarantined = Quarantine.ListAsync().GetAwaiter().GetResult().Count; } catch { }
        long recentAlerts = 0;
        try
        {
            var since = DateTimeOffset.UtcNow.AddDays(-1);
            recentAlerts = EventLog.ReadRecentAsync(500).GetAwaiter().GetResult()
                .Count(e => e.Timestamp >= since && e.Kind is "blocked" or "quarantine" or "anomaly" or "detection");
        }
        catch { }

        return new MachineStatus
        {
            MachineName = Environment.MachineName,
            Version = CurrentVersion.ToString(),
            RealTimeProtection = RealTime.IsRunning,
            BehaviorGuard = BehaviorWatch.IsRunning,
            ProcessMonitoring = ProcessWatch.IsRunning,
            AdaptiveLearning = Settings.AdaptiveLearningEnabled,
            SignatureCount = Signatures.Count,
            SignaturesUpdatedUtc = Signatures.LastUpdatedUtc,
            ThreatsHandled = ThreatsHandledTotal,
            InQuarantine = quarantined,
            RecentAlerts24h = recentAlerts,
            LearnerLearning = Learner.IsLearning,
            LearnerObservations = Learner.Observations,
        };
    }

    private static readonly HttpClient Http = new()
    {
        Timeout = TimeSpan.FromMinutes(10),
        DefaultRequestHeaders = { { "User-Agent", "MesaShield/0.2" } },
    };

    protected override async void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        // Self-install on first run from anywhere that isn't the install location.
        // If it installs and relaunches the installed copy, exit this instance now.
        if (Installer.EnsureInstalled(e.Args, out _))
        {
            Shutdown();
            return;
        }

        StartMinimized = e.Args.Contains("--minimized") || e.Args.Contains("--silent");
        Directory.CreateDirectory(DataDirectory);

        Settings = AppSettings.Load(SettingsPath);

        // Managed deployment: apply an admin-supplied config (fleet folder, update source, toggles)
        // shipped next to the app or in %ProgramData%\MesaShield. Applied every start so central
        // config stays authoritative on company machines.
        foreach (var configPath in new[]
                 {
                     Path.Combine(Path.GetDirectoryName(Environment.ProcessPath ?? "") ?? "", DeployConfig.FileName),
                     Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "MesaShield", DeployConfig.FileName),
                 })
        {
            DeployConfig.Load(configPath)?.ApplyTo(Settings);
        }
        EventLog = new ShieldEventLog(LogsDirectory);
        Quarantine = new QuarantineManager(QuarantineDirectory);
        Updater = new SignatureUpdater(Http, SignaturesDirectory);
        AppUpdater = new UpdateChecker(Http);
        Reputation = new ReputationClient(Http,
            Settings.CloudLookupEnabled ? Settings.VirusTotalApiKey : null,
            Settings.CloudMaliciousThreshold, ReputationCachePath);
        Amsi = new AmsiScanner();

        Patterns.LoadBuiltInRules();
        Patterns.LoadRulesDirectory(RulesDirectory);
        await Signatures.LoadAsync(SignaturesDirectory);

        // On-device anomaly learners (fully local) and offline ML classifier.
        Learner = AnomalyLearner.Load(AnomalyModelPath);
        NetworkLearner = NetworkAnomalyLearner.Load(NetworkModelPath);
        Classifier = MalwareClassifier.Load(ClassifierModelPath) ?? MalwareClassifier.Baseline();

        Engine = new ScanEngine(Signatures, Patterns, new HeuristicAnalyzer())
        {
            ScriptScanner = Settings.AmsiScriptScanningEnabled ? Amsi : null,
            Reputation = Settings.CloudLookupEnabled ? Reputation : null,
            Classifier = Settings.MlClassifierEnabled ? Classifier : null,
        };

        var realTimeOptions = Settings.ToScanOptions();
        realTimeOptions.ExcludedPaths.Add(DataDirectory);
        RealTime = new RealTimeProtector(Engine, Quarantine, EventLog, realTimeOptions);
        ProcessWatch = new ProcessWatcher(Engine, Quarantine, EventLog);
        Usb = new UsbWatcher(EventLog);
        Firewall = new FirewallManager(EventLog);
        BehaviorWatch = new BehaviorMonitor(Behavior, EventLog);

        Usb.DriveInserted += root => Current.Dispatcher.Invoke(() =>
        {
            if (Settings.UsbAutoScanEnabled) RealTime.AddWatch(root);
            if (Current.MainWindow is MainWindow window) window.OnUsbInserted(root);
        });
        Usb.DriveRemoved += root => Current.Dispatcher.Invoke(() => RealTime.RemoveWatch(root));

        // Feed every new process to the on-device learner; act on genuine anomalies (once past warm-up).
        ProcessWatch.ProcessObserved += obs =>
        {
            if (!Settings.AdaptiveLearningEnabled) return;
            var assessment = Learner.Observe(obs);
            _learnerObservationsSinceSave++;
            if (_learnerObservationsSinceSave >= 25)
            {
                _learnerObservationsSinceSave = 0;
                try { Learner.Save(AnomalyModelPath); } catch { /* best-effort */ }
            }
            if (!assessment.IsLearning && assessment.SuggestedSeverity is { } severity)
            {
                _ = EventLog.LogAsync(
                    severity == ThreatSeverity.Malicious ? "anomaly" : "detection",
                    $"Unusual for this machine ({assessment.Score:P0}): {string.Join("; ", assessment.Reasons)}",
                    obs.ExecutablePath, "Anomaly.Behavioral");
                Current.Dispatcher.Invoke(() => (Current.MainWindow as MainWindow)?.NotifyAnomaly(obs, assessment));
            }
        };

        // Apply protection toggles.
        if (Settings.RealTimeProtectionEnabled) RealTime.Start();
        if (Settings.ProcessMonitoringEnabled) ProcessWatch.Start();
        if (Settings.UsbAutoScanEnabled) Usb.Start();
        if (Settings.BehaviorGuardEnabled) BehaviorWatch.Start();

        // Deep ETW monitoring (elevated only; degrades gracefully otherwise).
        Etw = new EtwMonitor(Learner, NetworkLearner, EventLog);
        Etw.AnomalyDetected += (assessment, context) =>
        {
            ThreatsHandledTotal++;
            Current.Dispatcher.Invoke(() => (Current.MainWindow as MainWindow)?.NotifyDeepAnomaly(assessment, context));
        };
        if (Settings.EtwMonitoringEnabled) Etw.Start();

        // Keep the run-at-startup registry entry in sync with the setting.
        try
        {
            var exePath = Process.GetCurrentProcess().MainModule?.FileName;
            if (exePath is not null) StartupManager.SetEnabled(Settings.RunAtStartup, exePath);
        }
        catch { /* non-fatal */ }

        // Fleet reporting: publish this machine's status locally and to the shared folder.
        Fleet = new FleetReporter(StatusPathLocal, BuildMachineStatus)
        {
            SharedFolder = Settings.FleetReportingEnabled && !string.IsNullOrWhiteSpace(Settings.FleetSharedFolder)
                ? Settings.FleetSharedFolder : null,
        };
        try { Fleet.Report(); } catch { /* best-effort */ }
        _fleetTimer = new System.Threading.Timer(_ => { try { Fleet.Report(); } catch { } },
            null, TimeSpan.FromMinutes(5), TimeSpan.FromMinutes(5));

        Scheduler = new JobScheduler(Settings,
            onSignatureUpdate: RunScheduledSignatureUpdateAsync,
            onScheduledScan: RunScheduledScanAsync,
            onUpdateCheck: RunScheduledUpdateCheckAsync);
        Scheduler.Start();

        await EventLog.LogAsync("app", $"MesaShield {CurrentVersion} started.");

        // Zero-click first run: pull the full signature database in the background so the
        // user doesn't have to. Runs once; failures just leave it for the scheduled update.
        if (!Settings.FirstRunCompleted && Signatures.Count == 0)
            _ = FirstRunSetupAsync();
    }

    private static async Task FirstRunSetupAsync()
    {
        try
        {
            (Current.MainWindow as MainWindow)?.NotifyFirstRunStarted();
            await Updater.DownloadFullDatabaseAsync();
            await Signatures.LoadAsync(SignaturesDirectory);
            Settings.FirstRunCompleted = true;
            Settings.Save();
            await EventLog.LogAsync("update", $"First-run setup complete: {Signatures.Count:N0} signatures installed.");
            Current.Dispatcher.Invoke(() => (Current.MainWindow as MainWindow)?.NotifyFirstRunDone(Signatures.Count));
        }
        catch (Exception ex)
        {
            await EventLog.LogAsync("error", $"First-run signature download failed (will retry on schedule): {ex.Message}");
        }
    }

    private static async Task RunScheduledSignatureUpdateAsync()
    {
        try
        {
            await Updater.DownloadRecentAsync();
            await Signatures.LoadAsync(SignaturesDirectory);
            await EventLog.LogAsync("update", "Scheduled signature update completed.");
        }
        catch (Exception ex) { await EventLog.LogAsync("error", $"Scheduled signature update failed: {ex.Message}"); }
    }

    private static async Task RunScheduledScanAsync()
    {
        var targets = Settings.ScheduledScanScope == ScheduledScanScope.FullScan
            ? DriveInfo.GetDrives().Where(d => d.IsReady && d.DriveType is DriveType.Fixed)
                .Select(d => d.RootDirectory.FullName).ToArray()
            : QuickScanTargets();

        var options = Settings.ToScanOptions();
        options.ExcludedPaths.Add(DataDirectory);
        var summary = await Engine.ScanAsync(targets, options,
            onResult: async result =>
            {
                foreach (var finding in result.Findings.Where(f => f.Severity == ThreatSeverity.Malicious))
                    await Quarantine.QuarantineAsync(finding);
            });
        await EventLog.LogAsync("scan",
            $"Scheduled {Settings.ScheduledScanScope} scanned {summary.FilesScanned:N0} files, {summary.Findings.Count} finding(s).");
        Current.Dispatcher.Invoke(() => (Current.MainWindow as MainWindow)?.NotifyScheduledScanDone(summary));
    }

    private static async Task RunScheduledUpdateCheckAsync()
    {
        if (string.IsNullOrWhiteSpace(Settings.UpdateChannel)) return;
        var result = await AppUpdater.CheckAsync(Settings.UpdateChannel, CurrentVersion);
        if (result.UpdateAvailable)
        {
            await EventLog.LogAsync("update", $"App update available: v{result.Release!.Version}.");
            Current.Dispatcher.Invoke(() => (Current.MainWindow as MainWindow)?.NotifyUpdateAvailable(result.Release!));
        }
    }

    public static string[] QuickScanTargets()
    {
        var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        return new[]
        {
            Path.Combine(userProfile, "Downloads"),
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
            Path.GetTempPath(),
        }.Where(Directory.Exists).ToArray();
    }

    private static SemVer ResolveVersion()
    {
        var attr = Assembly.GetExecutingAssembly().GetName().Version;
        return attr is null ? new SemVer(0, 2, 0) : new SemVer(attr.Major, attr.Minor, attr.Build);
    }

    protected override void OnExit(ExitEventArgs e)
    {
        try { Learner?.Save(AnomalyModelPath); } catch { /* best-effort */ }
        try { NetworkLearner?.Save(NetworkModelPath); } catch { /* best-effort */ }
        _fleetTimer?.Dispose();
        Etw?.Dispose();
        Scheduler?.Dispose();
        RealTime?.Dispose();
        ProcessWatch?.Dispose();
        BehaviorWatch?.Dispose();
        Usb?.Dispose();
        Amsi?.Dispose();
        base.OnExit(e);
    }
}
