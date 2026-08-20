using System.Diagnostics;
using System.Net;
using System.Runtime.InteropServices;

namespace MesaShield.Windows;

/// <summary>
/// Live view of TCP connections mapped to the owning process, via the same
/// iphlpapi GetExtendedTcpTable API that netstat and Resource Monitor use.
/// This powers the "who is my computer talking to?" screen.
/// </summary>
public static class ConnectionMonitor
{
    public sealed record ConnectionInfo(
        int ProcessId, string ProcessName, string? ExecutablePath,
        IPEndPoint Local, IPEndPoint Remote, string State);

    private static readonly string[] TcpStates =
    {
        "UNKNOWN", "CLOSED", "LISTENING", "SYN_SENT", "SYN_RCVD", "ESTABLISHED",
        "FIN_WAIT1", "FIN_WAIT2", "CLOSE_WAIT", "CLOSING", "LAST_ACK", "TIME_WAIT", "DELETE_TCB",
    };

    /// <summary>Snapshot of current TCP connections with owning processes.</summary>
    public static List<ConnectionInfo> Snapshot(bool establishedOnly = true)
    {
        var connections = new List<ConnectionInfo>();
        var processNames = new Dictionary<int, (string Name, string? Path)>();

        foreach (var row in GetTcpRows())
        {
            var state = row.state < TcpStates.Length ? TcpStates[row.state] : "UNKNOWN";
            if (establishedOnly && state != "ESTABLISHED") continue;

            if (!processNames.TryGetValue(row.owningPid, out var proc))
            {
                proc = ResolveProcess(row.owningPid);
                processNames[row.owningPid] = proc;
            }

            connections.Add(new ConnectionInfo(
                row.owningPid, proc.Name, proc.Path,
                new IPEndPoint(row.localAddr, row.localPort),
                new IPEndPoint(row.remoteAddr, row.remotePort),
                state));
        }
        return connections
            .OrderBy(c => c.ProcessName, StringComparer.OrdinalIgnoreCase)
            .ThenBy(c => c.Remote.ToString())
            .ToList();
    }

    private static (string, string?) ResolveProcess(int pid)
    {
        try
        {
            using var process = Process.GetProcessById(pid);
            string? path = null;
            try { path = process.MainModule?.FileName; } catch { /* access denied on protected processes */ }
            return (process.ProcessName, path);
        }
        catch (ArgumentException)
        {
            return ($"pid {pid}", null);
        }
    }

    // ---- P/Invoke plumbing ------------------------------------------------

    private record struct TcpRow(int state, uint localAddr, int localPort, uint remoteAddr, int remotePort, int owningPid);

    private const int AF_INET = 2;
    private const int TCP_TABLE_OWNER_PID_ALL = 5;

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedTcpTable(
        IntPtr pTcpTable, ref int pdwSize, bool bOrder, int ulAf, int tableClass, uint reserved);

    [StructLayout(LayoutKind.Sequential)]
    private struct MIB_TCPROW_OWNER_PID
    {
        public uint state;
        public uint localAddr;
        public uint localPort;   // network byte order in low 16 bits
        public uint remoteAddr;
        public uint remotePort;
        public uint owningPid;
    }

    private static IEnumerable<TcpRow> GetTcpRows()
    {
        var size = 0;
        GetExtendedTcpTable(IntPtr.Zero, ref size, false, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
        var buffer = Marshal.AllocHGlobal(size);
        try
        {
            if (GetExtendedTcpTable(buffer, ref size, false, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) != 0)
                yield break;

            var rowCount = Marshal.ReadInt32(buffer);
            var rowPtr = buffer + 4;
            var rowSize = Marshal.SizeOf<MIB_TCPROW_OWNER_PID>();

            for (var i = 0; i < rowCount; i++)
            {
                var row = Marshal.PtrToStructure<MIB_TCPROW_OWNER_PID>(rowPtr + i * rowSize);
                yield return new TcpRow(
                    (int)row.state,
                    row.localAddr, NetworkPort(row.localPort),
                    row.remoteAddr, NetworkPort(row.remotePort),
                    (int)row.owningPid);
            }
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    private static int NetworkPort(uint port) => (int)(((port & 0xFF) << 8) | ((port >> 8) & 0xFF));
}
