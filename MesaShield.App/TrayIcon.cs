using System.Drawing;
using WinForms = System.Windows.Forms;
using Point = System.Drawing.Point;

namespace MesaShield.App;

/// <summary>
/// System-tray presence: a NotifyIcon with a right-click menu and balloon notifications.
/// Lets MesaShield run hands-off in the background while staying one click away.
/// </summary>
public sealed class TrayIcon : IDisposable
{
    private readonly WinForms.NotifyIcon _notifyIcon;

    public event Action? OpenRequested;
    public event Action? QuickScanRequested;
    public event Action<bool>? ProtectionToggleRequested; // true = enable
    public event Action? QuitRequested;

    public TrayIcon()
    {
        _notifyIcon = new WinForms.NotifyIcon
        {
            Icon = BuildShieldIcon(),
            Text = "MesaShield — protected",
            Visible = true,
        };
        _notifyIcon.DoubleClick += (_, _) => OpenRequested?.Invoke();

        var menu = new WinForms.ContextMenuStrip();
        menu.Items.Add("Open MesaShield", null, (_, _) => OpenRequested?.Invoke());
        menu.Items.Add("Quick scan now", null, (_, _) => QuickScanRequested?.Invoke());
        menu.Items.Add(new WinForms.ToolStripSeparator());
        var pauseItem = new WinForms.ToolStripMenuItem("Pause protection");
        pauseItem.Click += (_, _) =>
        {
            var enabling = pauseItem.Text.StartsWith("Resume");
            pauseItem.Text = enabling ? "Pause protection" : "Resume protection";
            ProtectionToggleRequested?.Invoke(enabling);
        };
        menu.Items.Add(pauseItem);
        menu.Items.Add(new WinForms.ToolStripSeparator());
        menu.Items.Add("Quit", null, (_, _) => QuitRequested?.Invoke());
        _notifyIcon.ContextMenuStrip = menu;
    }

    public void SetStatus(bool protectedOn) =>
        _notifyIcon.Text = protectedOn ? "MesaShield — protected" : "MesaShield — protection paused";

    /// <summary>Show a Windows balloon/toast notification from the tray.</summary>
    public void Notify(string title, string message, bool warning = false)
    {
        _notifyIcon.BalloonTipTitle = title;
        _notifyIcon.BalloonTipText = message;
        _notifyIcon.BalloonTipIcon = warning ? WinForms.ToolTipIcon.Warning : WinForms.ToolTipIcon.Info;
        _notifyIcon.ShowBalloonTip(6000);
    }

    /// <summary>Draw a simple shield glyph so we don't need an external .ico asset.</summary>
    private static Icon BuildShieldIcon()
    {
        using var bitmap = new Bitmap(32, 32);
        using (var g = Graphics.FromImage(bitmap))
        {
            g.SmoothingMode = System.Drawing.Drawing2D.SmoothingMode.AntiAlias;
            g.Clear(Color.Transparent);
            var shield = new[]
            {
                new Point(16, 2), new Point(29, 7), new Point(29, 16),
                new Point(16, 30), new Point(3, 16), new Point(3, 7),
            };
            using var fill = new SolidBrush(Color.FromArgb(59, 130, 246));
            g.FillPolygon(fill, shield);
            using var pen = new Pen(Color.White, 2.5f);
            g.DrawLines(pen, new[] { new Point(10, 16), new Point(15, 21), new Point(23, 10) });
        }
        return Icon.FromHandle(bitmap.GetHicon());
    }

    public void Dispose()
    {
        _notifyIcon.Visible = false;
        _notifyIcon.Dispose();
    }
}
