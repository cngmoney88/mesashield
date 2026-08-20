using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
using System.Windows;
using System.Windows.Controls;
using MesaShield.Core;
using MesaShield.Windows;
using MessageBox = System.Windows.MessageBox;
using Button = System.Windows.Controls.Button;

namespace MesaShield.App;

public partial class MainWindow : Window
{
    private readonly ObservableCollection<ThreatFinding> _findings = new();
    private CancellationTokenSource? _scanCts;
    private long _threatsHandled;
    private TrayIcon? _tray;
    private ReleaseInfo? _pendingUpdate;
    private bool _reallyClosing;

    public MainWindow()
    {
        InitializeComponent();
        FindingsList.ItemsSource = _findings;
        Loaded += async (_, _) => await InitializeAsync();
    }

    private async Task InitializeAsync()
    {
        while (App.Engine is null) await Task.Delay(50);

        VersionText.Text = $"MesaShield {App.CurrentVersion}";
        _tray = new TrayIcon();
        _tray.OpenRequested += ShowFromTray;
        _tray.QuickScanRequested += () => Dispatcher.Invoke(() => { ShowFromTray(); ShowPage("Scan"); QuickScan_Click(this, new RoutedEventArgs()); });
        _tray.ProtectionToggleRequested += enable => Dispatcher.Invoke(() => ToggleAllProtection(enable));
        _tray.QuitRequested += () => Dispatcher.Invoke(() => { _reallyClosing = true; Close(); });

        App.RealTime.ThreatHandled += (finding, quarantined) => Dispatcher.Invoke(() =>
        {
            _threatsHandled++;
            RefreshDashboardCounters();
            _ = RefreshActivityAsync();
            if (App.Settings.ShowNotifications)
                _tray?.Notify("Threat blocked", $"{finding.ThreatName}\n{Path.GetFileName(finding.FilePath)}", warning: true);
        });
        App.ProcessWatch.ProcessBlocked += (_, finding) => Dispatcher.Invoke(() =>
        {
            _threatsHandled++;
            RefreshDashboardCounters();
            if (App.Settings.ShowNotifications)
                _tray?.Notify("Program blocked", finding.ThreatName, warning: true);
        });
        App.BehaviorWatch.AlertRaised += alert => Dispatcher.Invoke(() =>
        {
            _threatsHandled++;
            RefreshDashboardCounters();
            _ = RefreshActivityAsync();
            if (App.Settings.ShowNotifications)
                _tray?.Notify(alert.Severity == ThreatSeverity.Malicious ? "⚠ Ransomware blocked" : "Suspicious activity", alert.Message, warning: true);
        });

        UpdateRealTimeCard();
        RefreshDashboardCounters();
        RefreshSignatureCard();
        await RefreshActivityAsync();
        await RefreshQuarantineAsync();
        LoadSettingsIntoUi();

        if (App.Signatures.Count == 0)
            UpdateStatusText.Text = "No signature database installed yet — open Settings to download it. " +
                                    "Pattern and heuristic detection work without it.";

        if (App.StartMinimized && App.Settings.StartMinimizedToTray)
            Hide();
    }

    public void OnUsbInserted(string root)
    {
        var answer = MessageBox.Show(
            $"Removable drive {root} was plugged in and is now being watched.\n\nRun a full scan of it now?",
            "MesaShield", MessageBoxButton.YesNo, MessageBoxImage.Question);
        if (answer == MessageBoxResult.Yes)
        {
            ShowPage("Scan");
            _ = RunScanAsync(new[] { root }, $"Scanning {root}");
        }
    }

    // ---- Notifications from background jobs -------------------------------

    public void NotifyFirstRunStarted()
    {
        if (App.Settings.ShowNotifications)
            _tray?.Notify("Setting up MesaShield", "Downloading the malware signature database in the background…");
        UpdateStatusText.Text = "First-time setup: downloading the full signature database…";
    }

    public void NotifyFirstRunDone(int count)
    {
        RefreshSignatureCard();
        UpdateStatusText.Text = $"Setup complete — {count:N0} signatures installed. Protection is fully active.";
        if (App.Settings.ShowNotifications)
            _tray?.Notify("MesaShield is ready", $"{count:N0} malware signatures installed. You're protected.");
    }

    public void NotifyAnomaly(MesaShield.Core.Ml.ProcessObservation obs, MesaShield.Core.Ml.AnomalyAssessment assessment)
    {
        _threatsHandled++;
        RefreshDashboardCounters();
        _ = RefreshActivityAsync();
        if (App.Settings.ShowNotifications)
            _tray?.Notify(
                assessment.SuggestedSeverity == ThreatSeverity.Malicious ? "⚠ Unusual activity blocked-worthy" : "Unusual activity",
                $"{System.IO.Path.GetFileName(obs.ExecutablePath)} — {string.Join("; ", assessment.Reasons)}",
                warning: true);
    }

    public void NotifyDeepAnomaly(MesaShield.Core.Ml.AnomalyAssessment assessment, string context)
    {
        _threatsHandled++;
        RefreshDashboardCounters();
        _ = RefreshActivityAsync();
        if (App.Settings.ShowNotifications)
            _tray?.Notify("Unusual activity (deep monitor)",
                $"{context} — {string.Join("; ", assessment.Reasons)}", warning: true);
    }

    public void NotifyScheduledScanDone(ScanSummary summary)
    {
        if (App.Settings.ShowNotifications)
            _tray?.Notify("Scheduled scan complete",
                $"{summary.FilesScanned:N0} files scanned, {summary.Findings.Count} finding(s).");
        RefreshDashboardCounters();
    }

    public void NotifyUpdateAvailable(ReleaseInfo release)
    {
        _pendingUpdate = release;
        UpdateBannerText.Text = $"MesaShield v{release.Version} is available." +
                                (string.IsNullOrWhiteSpace(release.Notes) ? "" : $" {release.Notes}");
        UpdateBanner.Visibility = Visibility.Visible;
        if (App.Settings.ShowNotifications)
            _tray?.Notify("Update available", $"MesaShield v{release.Version} is ready to install.");
    }

    // ---- Tray / minimize-to-tray -----------------------------------------

    private void ShowFromTray()
    {
        Show();
        WindowState = WindowState.Normal;
        Activate();
    }

    protected override void OnStateChanged(EventArgs e)
    {
        base.OnStateChanged(e);
        if (WindowState == WindowState.Minimized && App.Settings.StartMinimizedToTray)
            Hide();
    }

    protected override void OnClosing(CancelEventArgs e)
    {
        // Closing the window just hides to tray; real exit comes from the tray menu.
        if (!_reallyClosing)
        {
            e.Cancel = true;
            Hide();
            _tray?.Notify("Still protecting you", "MesaShield is running in the background. Right-click the tray icon to quit.");
            return;
        }
        _tray?.Dispose();
        base.OnClosing(e);
    }

    private void ToggleAllProtection(bool enable)
    {
        if (enable)
        {
            if (App.Settings.RealTimeProtectionEnabled) App.RealTime.Start();
            if (App.Settings.ProcessMonitoringEnabled) App.ProcessWatch.Start();
            if (App.Settings.BehaviorGuardEnabled) App.BehaviorWatch.Start();
        }
        else
        {
            App.RealTime.Stop();
            App.ProcessWatch.Dispose();
            App.BehaviorWatch.Stop();
        }
        _tray?.SetStatus(enable);
        UpdateRealTimeCard();
    }

    // ---- Navigation -------------------------------------------------------

    private void Nav_Click(object sender, RoutedEventArgs e) => ShowPage((string)((Button)sender).Tag);

    private void ShowPage(string page)
    {
        PageDashboard.Visibility = page == "Dashboard" ? Visibility.Visible : Visibility.Collapsed;
        PageScan.Visibility = page == "Scan" ? Visibility.Visible : Visibility.Collapsed;
        PageQuarantine.Visibility = page == "Quarantine" ? Visibility.Visible : Visibility.Collapsed;
        PageFirewall.Visibility = page == "Firewall" ? Visibility.Visible : Visibility.Collapsed;
        PageActivity.Visibility = page == "Activity" ? Visibility.Visible : Visibility.Collapsed;
        PageSettings.Visibility = page == "Settings" ? Visibility.Visible : Visibility.Collapsed;
        PageFleet.Visibility = page == "Fleet" ? Visibility.Visible : Visibility.Collapsed;

        if (page == "Quarantine") _ = RefreshQuarantineAsync();
        if (page == "Activity") _ = RefreshActivityAsync();
        if (page == "Firewall") RefreshConnections();
        if (page == "Fleet") RefreshFleet();
        if (page == "Dashboard") { RefreshDashboardCounters(); _ = RefreshActivityAsync(); }
    }

    // ---- Dashboard --------------------------------------------------------

    private void UpdateRealTimeCard()
    {
        var on = App.RealTime.IsRunning;
        RealTimeStatus.Text = on ? "On" : "Off";
        RealTimeStatus.Foreground = (System.Windows.Media.Brush)FindResource(on ? "GoodBrush" : "BadBrush");
        RealTimeToggle.Content = on ? "Turn off" : "Turn on";
    }

    private void RealTimeToggle_Click(object sender, RoutedEventArgs e)
    {
        if (App.RealTime.IsRunning) App.RealTime.Stop();
        else App.RealTime.Start();
        UpdateRealTimeCard();
    }

    private async void RefreshDashboardCounters()
    {
        ThreatCount.Text = _threatsHandled.ToString("N0");
        App.ThreatsHandledTotal = _threatsHandled;
        var entries = await App.Quarantine.ListAsync();
        QuarantineCount.Text = $"{entries.Count} in quarantine";
    }

    private void RefreshSignatureCard()
    {
        SignatureCount.Text = App.Signatures.Count.ToString("N0");
        SignatureUpdated.Text = App.Signatures.LastUpdatedUtc is { } updated
            ? $"Updated {updated.ToLocalTime():g}" : "Never updated";
    }

    // ---- Scan -------------------------------------------------------------

    private void QuickScan_Click(object sender, RoutedEventArgs e) =>
        _ = RunScanAsync(App.QuickScanTargets(), "Quick scan");

    private void FullScan_Click(object sender, RoutedEventArgs e)
    {
        var drives = DriveInfo.GetDrives()
            .Where(d => d.IsReady && d.DriveType is DriveType.Fixed or DriveType.Removable)
            .Select(d => d.RootDirectory.FullName).ToArray();
        _ = RunScanAsync(drives, "Full scan");
    }

    private void CustomScan_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new Microsoft.Win32.OpenFolderDialog { Title = "Choose a folder to scan" };
        if (dialog.ShowDialog() == true)
            _ = RunScanAsync(new[] { dialog.FolderName }, $"Scanning {dialog.FolderName}");
    }

    private void CancelScan_Click(object sender, RoutedEventArgs e) => _scanCts?.Cancel();

    private async Task RunScanAsync(string[] targets, string label)
    {
        if (_scanCts is not null) return;
        _scanCts = new CancellationTokenSource();
        _findings.Clear();
        SetScanUi(true, $"{label} — starting...");

        var options = App.Settings.ToScanOptions();
        options.ExcludedPaths.Add(App.DataDirectory);

        var progress = new Progress<ScanProgress>(p =>
        {
            ScanStatusText.Text = $"{label} — {p.FilesScanned:N0} files scanned, {p.ThreatsFound} finding(s)";
            ScanCurrentFile.Text = p.CurrentFile;
        });

        try
        {
            var summary = await App.Engine.ScanAsync(targets, options, progress,
                onResult: result =>
                {
                    foreach (var finding in result.Findings)
                        Dispatcher.Invoke(() => _findings.Add(finding));
                    return Task.CompletedTask;
                }, ct: _scanCts.Token);

            var duration = (summary.FinishedAt!.Value - summary.StartedAt).TotalMinutes;
            ScanStatusText.Text = summary.WasCancelled
                ? $"{label} cancelled after {summary.FilesScanned:N0} files."
                : $"{label} complete: {summary.FilesScanned:N0} files ({summary.BytesScanned / (1024.0 * 1024 * 1024):F1} GB) in {duration:F1} min — {summary.Findings.Count} finding(s).";
            await App.EventLog.LogAsync("scan", ScanStatusText.Text);
        }
        catch (Exception ex)
        {
            ScanStatusText.Text = $"Scan failed: {ex.Message}";
        }
        finally
        {
            _scanCts.Dispose();
            _scanCts = null;
            SetScanUi(false, ScanStatusText.Text);
        }
    }

    private void SetScanUi(bool scanning, string status)
    {
        ScanStatusText.Text = status;
        ScanProgressBar.IsIndeterminate = scanning;
        CancelScanButton.Visibility = scanning ? Visibility.Visible : Visibility.Collapsed;
        QuickScanButton.IsEnabled = FullScanButton.IsEnabled = CustomScanButton.IsEnabled = !scanning;
        if (!scanning) ScanCurrentFile.Text = "";
    }

    private async void QuarantineSelected_Click(object sender, RoutedEventArgs e) =>
        await QuarantineFindingsAsync(FindingsList.SelectedItems.Cast<ThreatFinding>().ToList());

    private async void QuarantineAll_Click(object sender, RoutedEventArgs e) =>
        await QuarantineFindingsAsync(_findings.Where(f => f.Severity == ThreatSeverity.Malicious).ToList());

    private async Task QuarantineFindingsAsync(List<ThreatFinding> findings)
    {
        var done = 0;
        foreach (var finding in findings)
        {
            var entry = await App.Quarantine.QuarantineAsync(finding);
            if (entry is not null)
            {
                done++; _threatsHandled++;
                _findings.Remove(finding);
                await App.EventLog.LogAsync("quarantine", $"Quarantined {finding.ThreatName}", finding.FilePath, finding.ThreatName);
            }
        }
        RefreshDashboardCounters();
        if (done > 0)
            MessageBox.Show($"{done} file(s) moved to quarantine.", "MesaShield", MessageBoxButton.OK, MessageBoxImage.Information);
    }

    // ---- Quarantine -------------------------------------------------------

    private sealed record QuarantineRow(string Id, string When, string ThreatName, string OriginalPath, string Size);

    private async Task RefreshQuarantineAsync()
    {
        var entries = await App.Quarantine.ListAsync();
        QuarantineList.ItemsSource = entries.OrderByDescending(q => q.QuarantinedAt)
            .Select(q => new QuarantineRow(q.Id, q.QuarantinedAt.ToLocalTime().ToString("g"), q.ThreatName, q.OriginalPath,
                q.OriginalSize < 1024 * 1024 ? $"{q.OriginalSize / 1024.0:F0} KB" : $"{q.OriginalSize / (1024.0 * 1024):F1} MB"))
            .ToList();
    }

    private async void RestoreQuarantine_Click(object sender, RoutedEventArgs e)
    {
        var rows = QuarantineList.SelectedItems.Cast<QuarantineRow>().ToList();
        if (rows.Count == 0) return;
        if (MessageBox.Show($"Restore {rows.Count} file(s)? Only do this if you're confident they were false positives.",
                "MesaShield", MessageBoxButton.YesNo, MessageBoxImage.Warning) != MessageBoxResult.Yes) return;
        foreach (var row in rows)
            if (await App.Quarantine.RestoreAsync(row.Id))
                await App.EventLog.LogAsync("restore", $"Restored from quarantine: {row.OriginalPath}", row.OriginalPath);
        await RefreshQuarantineAsync();
        RefreshDashboardCounters();
    }

    private async void DeleteQuarantine_Click(object sender, RoutedEventArgs e)
    {
        var rows = QuarantineList.SelectedItems.Cast<QuarantineRow>().ToList();
        if (rows.Count == 0) return;
        if (MessageBox.Show($"Permanently delete {rows.Count} file(s)? This cannot be undone.",
                "MesaShield", MessageBoxButton.YesNo, MessageBoxImage.Warning) != MessageBoxResult.Yes) return;
        foreach (var row in rows) await App.Quarantine.DeleteAsync(row.Id);
        await RefreshQuarantineAsync();
        RefreshDashboardCounters();
    }

    // ---- Firewall ---------------------------------------------------------

    private void RefreshConnections_Click(object sender, RoutedEventArgs e) => RefreshConnections();

    private void RefreshConnections()
    {
        try
        {
            ConnectionsList.ItemsSource = ConnectionMonitor.Snapshot();
            FirewallStateText.Text = App.Firewall.IsFirewallEnabled() ? "Windows Firewall: ON" : "⚠ Windows Firewall is OFF";
        }
        catch (Exception ex) { FirewallStateText.Text = $"Error: {ex.Message}"; }
    }

    private async void BlockApp_Click(object sender, RoutedEventArgs e)
    {
        if (ConnectionsList.SelectedItem is not ConnectionMonitor.ConnectionInfo c) return;
        if (c.ExecutablePath is null)
        {
            MessageBox.Show("Can't resolve that process's executable (protected system process).", "MesaShield");
            return;
        }
        try
        {
            await App.Firewall.BlockApplicationAsync(c.ExecutablePath, "Blocked by user.");
            MessageBox.Show($"Blocked {c.ProcessName}.", "MesaShield", MessageBoxButton.OK, MessageBoxImage.Information);
        }
        catch (UnauthorizedAccessException)
        {
            MessageBox.Show("Firewall changes need administrator rights. Restart MesaShield as administrator.", "MesaShield", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    private async void UnblockApp_Click(object sender, RoutedEventArgs e)
    {
        if (ConnectionsList.SelectedItem is not ConnectionMonitor.ConnectionInfo c || c.ExecutablePath is null) return;
        try
        {
            await App.Firewall.RemoveRulesForApplicationAsync(c.ExecutablePath);
            MessageBox.Show($"Removed MesaShield firewall rules for {c.ProcessName}.", "MesaShield", MessageBoxButton.OK, MessageBoxImage.Information);
        }
        catch (UnauthorizedAccessException)
        {
            MessageBox.Show("Firewall changes need administrator rights.", "MesaShield", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    // ---- Fleet ------------------------------------------------------------

    private sealed record FleetRow(string Machine, string Health, string Version, string Protection,
        string Signatures, string Alerts, string Quarantine, string Learning, string LastSeen);

    private void RefreshFleet_Click(object sender, RoutedEventArgs e) => RefreshFleet();

    private void RefreshFleet()
    {
        // Always publish our own latest status first so this machine appears current.
        try { App.Fleet.Report(); } catch { }

        var folder = App.Settings.FleetSharedFolder;
        if (string.IsNullOrWhiteSpace(folder))
        {
            FleetStatusText.Text = "No shared folder set. Add one in Settings (e.g. \\\\SERVER\\MesaShield\\status) so every machine's status shows here. Showing this machine only.";
            FleetList.ItemsSource = new[] { ToRow(BuildSelfStatus()) };
            return;
        }

        try
        {
            var machines = FleetReader.ReadAll(folder);
            if (machines.Count == 0)
            {
                FleetStatusText.Text = $"No machines have reported to {folder} yet. Install MesaShield on the other machines and point them at the same folder.";
                FleetList.ItemsSource = new[] { ToRow(BuildSelfStatus()) };
                return;
            }
            var atRisk = machines.Count(m => m.Health == "at-risk");
            var attention = machines.Count(m => m.Health == "attention");
            FleetStatusText.Text = $"{machines.Count} machine(s) — {machines.Count - atRisk - attention} protected, {attention} need attention, {atRisk} at risk.";
            FleetList.ItemsSource = machines.Select(ToRow).ToList();
        }
        catch (Exception ex)
        {
            FleetStatusText.Text = $"Can't read the shared folder: {ex.Message}";
        }
    }

    private static MachineStatus BuildSelfStatus()
    {
        try { return FleetReader.ReadAll(Path.GetDirectoryName(App.StatusPathLocal)!).FirstOrDefault() ?? Fallback(); }
        catch { return Fallback(); }

        static MachineStatus Fallback() => new() { MachineName = Environment.MachineName, Version = App.CurrentVersion.ToString(), RealTimeProtection = App.RealTime.IsRunning, SignatureCount = App.Signatures.Count };
    }

    private static FleetRow ToRow(MachineStatus s) => new(
        Machine: s.MachineName + (s.IsStale(TimeSpan.FromMinutes(30)) ? " (stale)" : ""),
        Health: s.Health switch { "protected" => "● Protected", "attention" => "▲ Attention", _ => "✖ At risk" },
        Version: s.Version,
        Protection: s.RealTimeProtection ? "On" : "OFF",
        Signatures: s.SignatureCount.ToString("N0"),
        Alerts: s.RecentAlerts24h.ToString(),
        Quarantine: s.InQuarantine.ToString(),
        Learning: s.LearnerLearning ? $"learning ({s.LearnerObservations})" : "active",
        LastSeen: s.ReportedUtc.ToLocalTime().ToString("g"));

    // ---- Activity ---------------------------------------------------------

    private sealed record ActivityRow(string Time, string Kind, string Message, string? FilePath);

    private void RefreshActivity_Click(object sender, RoutedEventArgs e) => _ = RefreshActivityAsync();

    private async Task RefreshActivityAsync()
    {
        var events = await App.EventLog.ReadRecentAsync(300);
        var rows = events.Select(evt => new ActivityRow(
            evt.Timestamp.ToLocalTime().ToString("g"), evt.Kind, evt.Message, evt.FilePath)).ToList();
        ActivityList.ItemsSource = rows;
        DashboardActivity.ItemsSource = rows.Take(12).ToList();
    }

    // ---- Signature updates ------------------------------------------------

    private async void FullUpdate_Click(object sender, RoutedEventArgs e) => await RunUpdateAsync(true);
    private async void QuickUpdate_Click(object sender, RoutedEventArgs e) => await RunUpdateAsync(false);

    private async Task RunUpdateAsync(bool full)
    {
        FullUpdateButton.IsEnabled = QuickUpdateButton.IsEnabled = false;
        var progress = new Progress<string>(m => UpdateStatusText.Text = m);
        try
        {
            var count = full ? await App.Updater.DownloadFullDatabaseAsync(progress)
                             : await App.Updater.DownloadRecentAsync(progress);
            await App.Signatures.LoadAsync(App.SignaturesDirectory);
            RefreshSignatureCard();
            UpdateStatusText.Text += $" Database now holds {App.Signatures.Count:N0} signatures.";
            await App.EventLog.LogAsync("update", $"Signature update ({(full ? "full" : "incremental")}): {count:N0} hashes.");
        }
        catch (Exception ex) { UpdateStatusText.Text = $"Update failed: {ex.Message}"; }
        finally { FullUpdateButton.IsEnabled = QuickUpdateButton.IsEnabled = true; }
    }

    // ---- App update banner ------------------------------------------------

    private async void CheckUpdate_Click(object sender, RoutedEventArgs e)
    {
        var channel = TxtUpdateChannel.Text.Trim();
        if (string.IsNullOrWhiteSpace(channel))
        {
            MessageBox.Show("Enter an update source first (a GitHub owner/repo or a manifest URL).", "MesaShield");
            return;
        }
        try
        {
            var result = await App.AppUpdater.CheckAsync(channel, App.CurrentVersion);
            if (result.UpdateAvailable) NotifyUpdateAvailable(result.Release!);
            else MessageBox.Show($"You're up to date (v{App.CurrentVersion}).", "MesaShield", MessageBoxButton.OK, MessageBoxImage.Information);
        }
        catch (Exception ex) { MessageBox.Show($"Update check failed: {ex.Message}", "MesaShield"); }
    }

    private async void DownloadUpdate_Click(object sender, RoutedEventArgs e)
    {
        if (_pendingUpdate is null) return;
        var target = Path.Combine(App.DataDirectory, "Updates");
        Directory.CreateDirectory(target);
        var fileName = Path.GetFileName(new Uri(_pendingUpdate.DownloadUrl).LocalPath);
        var dest = Path.Combine(target, string.IsNullOrEmpty(fileName) ? $"MesaShield-{_pendingUpdate.Version}.zip" : fileName);
        try
        {
            UpdateBannerText.Text = $"Downloading v{_pendingUpdate.Version}...";
            await App.AppUpdater.DownloadAsync(_pendingUpdate, dest);
            await App.EventLog.LogAsync("update", $"Downloaded app update v{_pendingUpdate.Version}.");

            // Apply automatically: swap the exe and relaunch. No manual steps.
            if (SelfUpdater.ApplyAndRestart(dest, out var message))
            {
                _reallyClosing = true;
                System.Windows.Application.Current.Shutdown();
            }
            else
            {
                MessageBox.Show(
                    $"Update downloaded to:\n{dest}\n\nAutomatic install couldn't start ({message}). " +
                    "You can run that file manually to finish updating.",
                    "MesaShield", MessageBoxButton.OK, MessageBoxImage.Information);
            }
        }
        catch (Exception ex) { MessageBox.Show($"Update failed: {ex.Message}", "MesaShield"); }
    }

    private void DismissBanner_Click(object sender, RoutedEventArgs e) => UpdateBanner.Visibility = Visibility.Collapsed;

    // ---- Settings ---------------------------------------------------------

    private void LoadSettingsIntoUi()
    {
        var s = App.Settings;
        ChkRealTime.IsChecked = s.RealTimeProtectionEnabled;
        ChkProcess.IsChecked = s.ProcessMonitoringEnabled;
        ChkBehavior.IsChecked = s.BehaviorGuardEnabled;
        ChkAmsi.IsChecked = s.AmsiScriptScanningEnabled;
        ChkUsb.IsChecked = s.UsbAutoScanEnabled;
        ChkCloud.IsChecked = s.CloudLookupEnabled;
        ChkAdaptive.IsChecked = s.AdaptiveLearningEnabled;
        ChkMl.IsChecked = s.MlClassifierEnabled;
        ChkEtw.IsChecked = s.EtwMonitoringEnabled;
        LearnerStatusText.Text = App.Learner.IsLearning
            ? $"Adaptive learning: still learning this machine's normal ({App.Learner.Observations} events seen; needs ~300 before it starts flagging)."
            : $"Adaptive learning: active — baseline from {App.Learner.Observations:N0} events. ML model: {App.Classifier?.Version ?? "none"}. Deep monitor: {App.Etw.Status}.";
        ChkAutoUpdate.IsChecked = s.AutoUpdateEnabled;
        ChkRunAtStartup.IsChecked = s.RunAtStartup;
        ChkNotifications.IsChecked = s.ShowNotifications;
        TxtVtKey.Text = s.VirusTotalApiKey ?? "";
        TxtUpdateChannel.Text = s.UpdateChannel;
        ChkFleet.IsChecked = s.FleetReportingEnabled;
        TxtFleetFolder.Text = s.FleetSharedFolder;

        foreach (var f in Enum.GetNames<ScheduleFrequency>()) { CmbScanFreq.Items.Add(f); CmbSigFreq.Items.Add(f); }
        foreach (var sc in Enum.GetNames<ScheduledScanScope>()) CmbScanScope.Items.Add(sc);
        CmbScanFreq.SelectedItem = s.ScanSchedule.Frequency.ToString();
        CmbSigFreq.SelectedItem = s.SignatureUpdateSchedule.Frequency.ToString();
        CmbScanScope.SelectedItem = s.ScheduledScanScope.ToString();
        TxtScanHour.Text = s.ScanSchedule.Hour.ToString();
        TxtSigHour.Text = s.SignatureUpdateSchedule.Hour.ToString();
    }

    private void SaveSettings_Click(object sender, RoutedEventArgs e)
    {
        var s = App.Settings;
        s.RealTimeProtectionEnabled = ChkRealTime.IsChecked == true;
        s.ProcessMonitoringEnabled = ChkProcess.IsChecked == true;
        s.BehaviorGuardEnabled = ChkBehavior.IsChecked == true;
        s.AmsiScriptScanningEnabled = ChkAmsi.IsChecked == true;
        s.UsbAutoScanEnabled = ChkUsb.IsChecked == true;
        s.CloudLookupEnabled = ChkCloud.IsChecked == true;
        s.AdaptiveLearningEnabled = ChkAdaptive.IsChecked == true;
        s.MlClassifierEnabled = ChkMl.IsChecked == true;
        s.EtwMonitoringEnabled = ChkEtw.IsChecked == true;
        s.AutoUpdateEnabled = ChkAutoUpdate.IsChecked == true;
        s.RunAtStartup = ChkRunAtStartup.IsChecked == true;
        s.ShowNotifications = ChkNotifications.IsChecked == true;
        s.VirusTotalApiKey = string.IsNullOrWhiteSpace(TxtVtKey.Text) ? null : TxtVtKey.Text.Trim();
        s.UpdateChannel = TxtUpdateChannel.Text.Trim();
        s.FleetReportingEnabled = ChkFleet.IsChecked == true;
        s.FleetSharedFolder = TxtFleetFolder.Text.Trim();

        if (Enum.TryParse<ScheduleFrequency>((string?)CmbScanFreq.SelectedItem, out var sf)) s.ScanSchedule.Frequency = sf;
        if (Enum.TryParse<ScheduleFrequency>((string?)CmbSigFreq.SelectedItem, out var uf)) s.SignatureUpdateSchedule.Frequency = uf;
        if (Enum.TryParse<ScheduledScanScope>((string?)CmbScanScope.SelectedItem, out var scope)) s.ScheduledScanScope = scope;
        if (int.TryParse(TxtScanHour.Text, out var sh) && sh is >= 0 and <= 23) s.ScanSchedule.Hour = sh;
        if (int.TryParse(TxtSigHour.Text, out var uh) && uh is >= 0 and <= 23) s.SignatureUpdateSchedule.Hour = uh;

        s.Save();
        ApplyLiveSettings();
        MessageBox.Show("Settings saved and applied.", "MesaShield", MessageBoxButton.OK, MessageBoxImage.Information);
    }

    /// <summary>Apply settings that can change while running (start/stop modules, startup entry, engine hooks).</summary>
    private void ApplyLiveSettings()
    {
        var s = App.Settings;

        if (s.RealTimeProtectionEnabled && !App.RealTime.IsRunning) App.RealTime.Start();
        else if (!s.RealTimeProtectionEnabled && App.RealTime.IsRunning) App.RealTime.Stop();

        if (s.BehaviorGuardEnabled && !App.BehaviorWatch.IsRunning) App.BehaviorWatch.Start();
        else if (!s.BehaviorGuardEnabled && App.BehaviorWatch.IsRunning) App.BehaviorWatch.Stop();

        if (s.ProcessMonitoringEnabled && !App.ProcessWatch.IsRunning) App.ProcessWatch.Start();
        else if (!s.ProcessMonitoringEnabled && App.ProcessWatch.IsRunning) App.ProcessWatch.Dispose();

        App.Engine.ScriptScanner = s.AmsiScriptScanningEnabled ? App.Amsi : null;
        App.Engine.Reputation = s.CloudLookupEnabled ? App.Reputation : null;
        App.Engine.Classifier = s.MlClassifierEnabled ? App.Classifier : null;
        App.Fleet.SharedFolder = s.FleetReportingEnabled && !string.IsNullOrWhiteSpace(s.FleetSharedFolder) ? s.FleetSharedFolder : null;
        try { App.Fleet.Report(); } catch { }

        if (s.EtwMonitoringEnabled && !App.Etw.IsRunning) App.Etw.Start();
        else if (!s.EtwMonitoringEnabled && App.Etw.IsRunning) App.Etw.Dispose();

        try
        {
            var exePath = System.Diagnostics.Process.GetCurrentProcess().MainModule?.FileName;
            if (exePath is not null) StartupManager.SetEnabled(s.RunAtStartup, exePath);
        }
        catch { /* non-fatal */ }

        UpdateRealTimeCard();
    }
}
