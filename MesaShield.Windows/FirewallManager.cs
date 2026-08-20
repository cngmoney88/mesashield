using MesaShield.Core;

namespace MesaShield.Windows;

/// <summary>
/// Manages Windows Firewall rules through the HNetCfg.FwPolicy2 COM API — the same
/// interface the built-in firewall UI uses. MesaShield rules are grouped under
/// "MesaShield" so they're easy to identify and clean up. Requires elevation to
/// add/remove rules; reading works as a standard user.
/// </summary>
public sealed class FirewallManager
{
    private const string RuleGroup = "MesaShield";
    private readonly ShieldEventLog _log;

    public FirewallManager(ShieldEventLog log) => _log = log;

    public sealed record FirewallRuleInfo(
        string Name, string? ApplicationName, bool Enabled, bool Allow, bool Outbound,
        string? RemoteAddresses, string? RemotePorts, bool IsMesaShieldRule);

    private static dynamic CreatePolicy()
    {
        var type = Type.GetTypeFromProgID("HNetCfg.FwPolicy2")
            ?? throw new PlatformNotSupportedException("Windows Firewall COM API not available.");
        return Activator.CreateInstance(type)!;
    }

    /// <summary>Is the Windows Firewall on for the current profile?</summary>
    public bool IsFirewallEnabled()
    {
        dynamic policy = CreatePolicy();
        int currentProfiles = policy.CurrentProfileTypes;
        // Check each active profile bit (1=domain, 2=private, 4=public).
        foreach (var profile in new[] { 1, 2, 4 })
        {
            if ((currentProfiles & profile) != 0 && !(bool)policy.FirewallEnabled[profile])
                return false;
        }
        return true;
    }

    /// <summary>List all firewall rules (system + MesaShield).</summary>
    public List<FirewallRuleInfo> ListRules(bool mesaShieldOnly = false)
    {
        dynamic policy = CreatePolicy();
        var rules = new List<FirewallRuleInfo>();
        foreach (dynamic rule in policy.Rules)
        {
            string? grouping = null;
            try { grouping = rule.Grouping as string; } catch { }
            var isOurs = string.Equals(grouping, RuleGroup, StringComparison.OrdinalIgnoreCase);
            if (mesaShieldOnly && !isOurs) continue;

            rules.Add(new FirewallRuleInfo(
                Name: rule.Name ?? "(unnamed)",
                ApplicationName: rule.ApplicationName as string,
                Enabled: rule.Enabled,
                Allow: (int)rule.Action == 1,          // NET_FW_ACTION_ALLOW
                Outbound: (int)rule.Direction == 2,    // NET_FW_RULE_DIR_OUT
                RemoteAddresses: rule.RemoteAddresses as string,
                RemotePorts: rule.RemotePorts as string,
                IsMesaShieldRule: isOurs));
        }
        return rules;
    }

    /// <summary>Block all network traffic (in and out) for an application. Requires elevation.</summary>
    public async Task BlockApplicationAsync(string exePath, string? reason = null)
    {
        AddRule($"Block {Path.GetFileName(exePath)} (outbound)", exePath, allow: false, outbound: true);
        AddRule($"Block {Path.GetFileName(exePath)} (inbound)", exePath, allow: false, outbound: false);
        await _log.LogAsync("firewall", $"Blocked application: {exePath}. {reason}".TrimEnd(), exePath);
    }

    /// <summary>Explicitly allow an application through the firewall. Requires elevation.</summary>
    public async Task AllowApplicationAsync(string exePath)
    {
        AddRule($"Allow {Path.GetFileName(exePath)} (outbound)", exePath, allow: true, outbound: true);
        AddRule($"Allow {Path.GetFileName(exePath)} (inbound)", exePath, allow: true, outbound: false);
        await _log.LogAsync("firewall", $"Allowed application: {exePath}", exePath);
    }

    /// <summary>Remove every MesaShield rule that references the given application.</summary>
    public async Task RemoveRulesForApplicationAsync(string exePath)
    {
        dynamic policy = CreatePolicy();
        var toRemove = new List<string>();
        foreach (dynamic rule in policy.Rules)
        {
            string? grouping = null, app = null;
            try { grouping = rule.Grouping as string; app = rule.ApplicationName as string; } catch { }
            if (string.Equals(grouping, RuleGroup, StringComparison.OrdinalIgnoreCase) &&
                string.Equals(app, exePath, StringComparison.OrdinalIgnoreCase))
            {
                toRemove.Add((string)rule.Name);
            }
        }
        foreach (var name in toRemove) policy.Rules.Remove(name);
        await _log.LogAsync("firewall", $"Removed {toRemove.Count} rule(s) for {exePath}", exePath);
    }

    private static void AddRule(string name, string exePath, bool allow, bool outbound)
    {
        var ruleType = Type.GetTypeFromProgID("HNetCfg.FWRule")
            ?? throw new PlatformNotSupportedException("Windows Firewall COM API not available.");
        dynamic rule = Activator.CreateInstance(ruleType)!;
        rule.Name = name;
        rule.ApplicationName = exePath;
        rule.Action = allow ? 1 : 0;         // NET_FW_ACTION_ALLOW / BLOCK
        rule.Direction = outbound ? 2 : 1;   // OUT / IN
        rule.Enabled = true;
        rule.Grouping = RuleGroup;
        rule.Profiles = 0x7FFFFFFF;          // all profiles

        dynamic policy = CreatePolicy();
        policy.Rules.Add(rule);
    }
}
