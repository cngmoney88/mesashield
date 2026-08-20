using System.Diagnostics;
using System.IO;
using System.Net.Http;
using System.Reflection;
using System.Windows;
using MesaShield.Core;
using MesaShield.Core.Incidents;
using MesaShield.Core.Ml;
using MesaShield.Core.Privacy;
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
    public static IncidentStore Incidents { get; private set; } = null!;
    public static string IncidentsDirectory => Path.Combine(DataDirectory, "Incidents");

    /// <summary>Reconstruct and save the story around a detection, then surface it in the UI.</summary>
    public static async Task RecordIncidentAsync(string kind, string message, string? file, string? threat)
    {
        try
        {
            var trigger = new ShieldEventLog.ShieldEvent(DateTimeOffset.UtcNow, kind, message, file, threat);
            var recent = await EventLog.ReadRecentAsync(300);
            var incident = IncidentBuilder.Build(trigger, recent, TimeSpan.FromMinutes(10));
            Incidents.Save(incident);
            Current.Dispatcher.Invoke(() => (Current.MainWindow as MainWindow)?.OnIncident(incident));
        }
        catch (Exception ex) { await EventLog.LogAsync("error", $"Incident recording failed: {ex.Message}"); }
    }
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
    public static MesaShield.Core.Net.EgressGuard Egress { get; private set; } = null!;
    public static EgressWatcher EgressWatch { get; private set; } = null!;
    public static string EgressStatePath => Path.Combine(DataDirectory, "Models", "egress.json");
    public static MalwareClassifier? Classifier { get; private set; }
    public static BenignAnomalyModel? BenignModel { get; private set; }
    public static EtwMonitor Etw { get; private set; } = null!;
    public static FleetReporter Fleet { get; private set; } = null!;
    public static long ThreatsHandledTotal;

    public static string StatusPathLocal => Path.Combine(DataDirectory, "status.json");
    public static string NetworkModelPath => Path.Combine(DataDirectory, "Models", "network.json");
    public static string BenignModelPath => Path.Combine(DataDirectory, "Models", "benign.json");

    public static string AnomalyModelPath => Path.Combine(DataDirectory, "Models", "anomaly.json");
    public static string ClassifierModelPath => Path.Combine(DataDirectory, "Models", "classifier.json");

    public static bool StartMinimized { get; private set; }
    private static int _learnerObservationsSinceSave;
    private static System.Threading.Timer? _fleetTimer;
    private static System.Threading.Timer? _fleetCommandTimer;

    /// <summary>Reload the benign model from disk after (re)training and wire it into the engine.</summary>
    public static void ReloadBenignModel()
    {
        BenignModel = BenignAnomalyModel.Load(BenignModelPath);
        if (Engine is not null) Engine.BenignModel = Settings.MlClassifierEnabled ? BenignModel : null;
    }

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
            DeepMonitoring = Etw?.IsRunning ?? false,
            Elevated = ElevationManager.IsElevated,
            EgressMode = Settings.EgressMode.ToString(),
            PrivacyMode = Settings.PrivacyMode.ToString(),
            EgressBlocks24h = EgressBlocks24hCount(),
        };
    }

    /// <summary>Execute any fleet commands the dashboard pushed to this machine, then ack them.</summary>
    private static void ProcessFleetCommands()
    {
        var shared = Settings.FleetSharedFolder;
        if (string.IsNullOrWhiteSpace(shared) || !Settings.FleetReportingEnabled) return;
        var me = Environment.MachineName;

        foreach (var cmd in FleetCommander.Pending(shared, me))
        {
            try
            {
                switch (cmd.Type)
                {
                    case FleetCommandType.QuickScan:
                        _ = RunScheduledScanAsync(); break;
                    case FleetCommandType.FullScan:
                        var prev = Settings.ScheduledScanScope; Settings.ScheduledScanScope = ScheduledScanScope.FullScan;
                        _ = RunScheduledScanAsync().ContinueWith(_ => Settings.ScheduledScanScope = prev); break;
                    case FleetCommandType.UpdateSignatures:
                        _ = RunScheduledSignatureUpdateAsync(); break;
                    case FleetCommandType.CheckAppUpdate:
                        _ = RunScheduledUpdateCheckAsync(); break;
                    case FleetCommandType.SetPrivacyMode:
                        if (Enum.TryParse<PrivacyMode>(cmd.Arg, out var pm)) { Settings.PrivacyMode = pm; Privacy.Mode = pm; Settings.Save(); } break;
                    case FleetCommandType.SetEgressMode:
                        if (Enum.TryParse<MesaShield.Core.Net.EgressMode>(cmd.Arg, out var em))
                        {
                            Settings.EgressMode = em; Egress.Mode = em; Settings.Save();
                            if (em != MesaShield.Core.Net.EgressMode.Off && !EgressWatch.IsRunning) EgressWatch.Start();
                        }
                        break;
                    case FleetCommandType.Ping:
                        break;
                }
                _ = EventLog.LogAsync("fleet", $"Ran fleet command {cmd.Type} (from {cmd.IssuedBy}).");
            }
            catch (Exception ex) { _ = EventLog.LogAsync("error", $"Fleet command {cmd.Type} failed: {ex.Message}"); }
            finally { FleetCommander.Ack(shared, cmd.Id, me); }
        }

        try { FleetCommander.Cleanup(shared, TimeSpan.FromDays(7)); } catch { }
        try { Fleet.Report(); } catch { }   // refresh our status right after acting
    }

    private static long EgressBlocks24hCount()
    {
        try
        {
            var since = DateTimeOffset.UtcNow.AddDays(-1);
            return EventLog.ReadRecentAsync(500).GetAwaiter().GetResult()
                .Count(e => e.Timestamp >= since && e.Kind == "egress" && e.Message.StartsWith("BLOCK", StringComparison.OrdinalIgnoreCase));
        }
        catch { return 0; }
    }

    /// <summary>The single network-policy chokepoint. Every outbound request passes through it.</summary>
    public static PrivacyGuard Privacy { get; } = new();

    public static string PrivacyAuditPath => Path.Combine(LogsDirectory, "network-audit.jsonl");

    private static readonly HttpClient Http = new(new PrivacyHandler(Privacy, new HttpClientHandler()))
    {
        Timeout = TimeSpan.FromMinutes(10),
        // Deliberately generic User-Agent — no machine name, user, or version fingerprint leaks.
        DefaultRequestHeaders = { { "User-Agent", "MesaShield" } },
    };

    private static Mutex? _singleInstance;
    private static EventWaitHandle? _showSignal;

    protected override async void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        // Self-install on first run from anywhere that isn't the install location.
        // If it installs and relaunches the installed copy, exit this instance now.
        // (Done before the single-instance guard so the transient installer never holds the lock.)
        if (Installer.EnsureInstalled(e.Args, out _))
        {
            Shutdown();
            return;
        }

        // Single instance: if MesaShield is already running, bring that one window to the front
        // and exit. There is only ever one app and one window.
        _singleInstance = new Mutex(false, "MesaShield.SingleInstance.v1");
        _showSignal = new EventWaitHandle(false, EventResetMode.AutoReset, "MesaShield.ShowWindow.v1");
        bool owns;
        try { owns = _singleInstance.WaitOne(TimeSpan.Zero); }
        catch (AbandonedMutexException) { owns = true; }   // previous instance was killed — we own it now
        if (!owns)
        {
            _showSignal.Set();     // tell the already-running instance to surface its window
            Shutdown();
            return;
        }
        new Thread(() =>
        {
            while (_showSignal!.WaitOne())
                Current.Dispatcher.Invoke(() => (Current.MainWindow as MainWindow)?.BringToFront());
        }) { IsBackground = true, Name = "MesaShield-ShowListener" }.Start();

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

        // Privacy: apply the network policy and record every outbound decision to an audit log.
        Privacy.Mode = Settings.PrivacyMode;
        Directory.CreateDirectory(LogsDirectory);
        Privacy.Decision += entry =>
        {
            try
            {
                File.AppendAllText(PrivacyAuditPath,
                    System.Text.Json.JsonSerializer.Serialize(entry) + Environment.NewLine);
            }
            catch { /* audit logging is best-effort */ }
        };
        try { EventLog.PurgeOlderThan(Settings.LogRetentionDays); } catch { }
        Quarantine = new QuarantineManager(QuarantineDirectory);
        Incidents = new IncidentStore(IncidentsDirectory);
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
        BenignModel = BenignAnomalyModel.Load(BenignModelPath);

        Engine = new ScanEngine(Signatures, Patterns, new HeuristicAnalyzer())
        {
            ScriptScanner = Settings.AmsiScriptScanningEnabled ? Amsi : null,
            Reputation = Settings.CloudLookupEnabled ? Reputation : null,
            Classifier = Settings.MlClassifierEnabled ? Classifier : null,
            BenignModel = Settings.MlClassifierEnabled ? BenignModel : null,
        };

        var realTimeOptions = Settings.ToScanOptions();
        realTimeOptions.ExcludedPaths.Add(DataDirectory);
        RealTime = new RealTimeProtector(Engine, Quarantine, EventLog, realTimeOptions);
        ProcessWatch = new ProcessWatcher(Engine, Quarantine, EventLog);
        Usb = new UsbWatcher(EventLog);
        Firewall = new FirewallManager(EventLog);
        BehaviorWatch = new BehaviorMonitor(Behavior, EventLog);

        // Egress / data-loss-prevention: watch outbound connections and block data leaving to
        // unapproved destinations, learning each machine's normal network behavior.
        Egress = new MesaShield.Core.Net.EgressGuard(NetworkLearner) { Mode = Settings.EgressMode };
        Egress.Load(EgressStatePath);
        Egress.Mode = Settings.EgressMode;   // settings win over persisted mode
        EgressWatch = new EgressWatcher(Egress, Firewall, EventLog);
        // Surface EVERY outbound connection (allowed, watched, or blocked) so the Traffic screen
        // shows live activity and you can see exactly where data is going.
        EgressWatch.Decision += decision => Current.Dispatcher.Invoke(() =>
            (Current.MainWindow as MainWindow)?.OnEgressDecision(decision));

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
        if (Settings.EgressMode != MesaShield.Core.Net.EgressMode.Off) EgressWatch.Start();

        // Deep ETW monitoring (elevated only; degrades gracefully otherwise).
        Etw = new EtwMonitor(Learner, NetworkLearner, EventLog);
        Etw.AnomalyDetected += (assessment, context) =>
        {
            ThreatsHandledTotal++;
            Current.Dispatcher.Invoke(() => (Current.MainWindow as MainWindow)?.NotifyDeepAnomaly(assessment, context));
        };
        if (Settings.EtwMonitoringEnabled) Etw.Start();

        // If we're running elevated, make deep monitoring permanent: register a scheduled task
        // that relaunches MesaShield elevated at every logon with no further prompts.
        if (ElevationManager.IsElevated)
        {
            try
            {
                var exe = Environment.ProcessPath;
                if (exe is not null && !ElevationManager.ElevatedAutostartExists())
                {
                    ElevationManager.InstallElevatedAutostart(exe);
                    await EventLog.LogAsync("etw", "Deep monitoring enabled permanently — MesaShield will run elevated at every logon.");
                }
            }
            catch { /* non-fatal */ }
        }

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

        // Fleet command channel: poll the shared folder for commands the dashboard pushed to us.
        _fleetCommandTimer = new System.Threading.Timer(_ => { try { ProcessFleetCommands(); } catch { } },
            null, TimeSpan.FromSeconds(20), TimeSpan.FromSeconds(45));

        Scheduler = new JobScheduler(Settings,
            onSignatureUpdate: RunScheduledSignatureUpdateAsync,
            onScheduledScan: RunScheduledScanAsync,
            onUpdateCheck: RunScheduledUpdateCheckAsync);
        Scheduler.Start();
        StartSelfDefense();

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
            // Prefer a local mirror if configured (keeps offline machines off the internet entirely).
            if (!string.IsNullOrWhiteSpace(Settings.LocalSignatureMirror))
            {
                var installed = Updater.InstallFromLocalMirror(Settings.LocalSignatureMirror);
                await Signatures.LoadAsync(SignaturesDirectory);
                await EventLog.LogAsync("update", $"Signatures updated from local mirror ({installed} file(s)).");
                return;
            }
            if (Settings.PrivacyMode == PrivacyMode.Offline)
            {
                await EventLog.LogAsync("update", "Offline mode: skipped internet signature update (set a local mirror to update).");
                return;
            }
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
        if (string.IsNullOrWhiteSpace(Settings.UpdateChannel) || !Settings.AutoUpdateEnabled) return;
        var result = await AppUpdater.CheckAsync(Settings.UpdateChannel, CurrentVersion);
        if (!result.UpdateAvailable) return;

        var release = result.Release!;
        await EventLog.LogAsync("update", $"App update available: v{release.Version}.");

        if (Settings.AutoInstallUpdates)
        {
            await AutoInstallUpdateAsync(release);   // fully hands-off — download, verify, install, relaunch
        }
        else
        {
            Current.Dispatcher.Invoke(() => (Current.MainWindow as MainWindow)?.NotifyUpdateAvailable(release));
        }
    }

    /// <summary>Download, verify, and install an update with no user interaction (background auto-update).</summary>
    private static async Task AutoInstallUpdateAsync(ReleaseInfo release)
    {
        try
        {
            var version = release.Version.TrimStart('v', 'V');
            var dir = Path.Combine(DataDirectory, "Updates");
            Directory.CreateDirectory(dir);
            var fileName = Path.GetFileName(new Uri(release.DownloadUrl).LocalPath);
            if (string.IsNullOrEmpty(fileName)) fileName = "MesaShield-Setup.exe";
            var dest = Path.Combine(dir, fileName);

            // DownloadAsync verifies the SHA-256 from the manifest before returning.
            await AppUpdater.DownloadAsync(release, dest);

            // Downgrade guard: never auto-install something not strictly newer.
            try
            {
                var info = System.Diagnostics.FileVersionInfo.GetVersionInfo(dest);
                var dv = new Version(info.FileMajorPart, info.FileMinorPart, info.FileBuildPart);
                var cur = new Version(CurrentVersion.Major, CurrentVersion.Minor, CurrentVersion.Patch);
                if (dv <= cur) { await EventLog.LogAsync("update", $"Skipped auto-install: served v{dv} is not newer than v{cur}."); return; }
            }
            catch { }

            // Strip the internet "mark of the web" (after the hash check) so no SmartScreen prompt.
            MarkOfTheWeb.Remove(dest);

            await EventLog.LogAsync("update", $"Auto-installing update v{version} (silent).");
            Current.Dispatcher.Invoke(() =>
            {
                if (SelfUpdater.LaunchInstaller(dest, out _))
                {
                    (Current.MainWindow as MainWindow)?.PrepareForSilentRestart();
                    Current.Shutdown();
                }
            });
        }
        catch (Exception ex)
        {
            await EventLog.LogAsync("error", $"Auto-update failed: {ex.Message}");
        }
    }

    /// <summary>Erase everything MesaShield has learned or recorded on this machine (privacy control).</summary>
    public static void EraseAllLearnedData()
    {
        foreach (var f in new[] { AnomalyModelPath, NetworkModelPath, BenignModelPath })
            try { if (File.Exists(f)) File.Delete(f); } catch { }
        try { if (Directory.Exists(LogsDirectory)) foreach (var f in Directory.EnumerateFiles(LogsDirectory)) File.Delete(f); } catch { }

        // Reset in-memory learners so nothing lingers this session.
        Learner = AnomalyLearner.Load(AnomalyModelPath);
        NetworkLearner = NetworkAnomalyLearner.Load(NetworkModelPath);
        BenignModel = BenignAnomalyModel.Load(BenignModelPath);
        _ = EventLog.LogAsync("privacy", "All learned data and logs erased at user request.");
    }

    private static CancellationTokenSource? _selfDefenseCts;

    /// <summary>
    /// Self-defense: every minute, confirm each protection module that's supposed to be on is
    /// actually running — and restart it if something stopped it (a tamper attempt). Also
    /// re-registers the elevated autostart task if it was removed. Real malware disables the AV
    /// first; this makes MesaShield fight back.
    /// </summary>
    private static void StartSelfDefense()
    {
        _selfDefenseCts = new CancellationTokenSource();
        var ct = _selfDefenseCts.Token;
        _ = Task.Run(async () =>
        {
            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(TimeSpan.FromMinutes(1), ct);

                    void Heal(string name, bool shouldRun, bool isRunning, Action restart)
                    {
                        if (shouldRun && !isRunning)
                        {
                            restart();
                            _ = EventLog.LogAsync("tamper", $"Protection module '{name}' was not running and has been restarted.");
                            Current.Dispatcher.Invoke(() =>
                                (Current.MainWindow as MainWindow)?.NotifyTamper(name));
                        }
                    }

                    Heal("Real-time protection", Settings.RealTimeProtectionEnabled, RealTime.IsRunning, () => RealTime.Start());
                    Heal("Process monitoring", Settings.ProcessMonitoringEnabled, ProcessWatch.IsRunning, () => ProcessWatch.Start());
                    Heal("Ransomware guard", Settings.BehaviorGuardEnabled, BehaviorWatch.IsRunning, () => BehaviorWatch.Start());
                    Heal("Egress control", Settings.EgressMode != MesaShield.Core.Net.EgressMode.Off, EgressWatch.IsRunning, () => EgressWatch.Start());

                    // Re-register the elevated autostart if it was removed (only possible while elevated).
                    if (ElevationManager.IsElevated && !ElevationManager.ElevatedAutostartExists())
                    {
                        var exe = Environment.ProcessPath;
                        if (exe is not null) { ElevationManager.InstallElevatedAutostart(exe);
                            _ = EventLog.LogAsync("tamper", "Elevated autostart was missing and has been re-registered."); }
                    }
                }
                catch (OperationCanceledException) { break; }
                catch { /* keep watching */ }
            }
        }, ct);
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
        try { Egress?.Save(EgressStatePath); } catch { /* best-effort */ }
        EgressWatch?.Dispose();
        _fleetTimer?.Dispose();
        _fleetCommandTimer?.Dispose();
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
