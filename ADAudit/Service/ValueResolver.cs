using System.Collections.Concurrent;
using System.DirectoryServices.Protocols;
using System.Globalization;
using System.Security.Principal;
using System.Text.RegularExpressions;
using ADAudit.Shared;

namespace ADAudit.Service;

/// <summary>
/// Turns raw AD values into something readable when entries are shown (the stored trail stays untouched):
/// RIDs / SIDs → account names, flag numbers → flag names, FILETIMEs → dates, gPLink / GPO GUIDs → GPO names.
/// Lookups go to the local DC as SYSTEM and are cached.
/// </summary>
sealed class ValueResolver
{
    static readonly Regex SidRx = new(@"S-1-5-21-\d+-\d+-\d+-\d+|S-1-5-32-\d+|S-1-5-\d{1,2}\b", RegexOptions.Compiled);
    static readonly Regex GpLinkRx = new(@"\[LDAP://(?<dn>[^;\]]+);(?<opt>\d+)\]", RegexOptions.Compiled | RegexOptions.IgnoreCase);
    static readonly Regex GuidRx = new(@"\{[0-9A-Fa-f\-]{36}\}", RegexOptions.Compiled);

    static readonly HashSet<string> FileTimeAttrs = new(StringComparer.OrdinalIgnoreCase)
        { "accountExpires", "pwdLastSet", "lockoutTime", "lastLogonTimestamp", "lastLogon", "badPasswordTime", "msDS-LastSuccessfulInteractiveLogonTime" };

    readonly ConcurrentDictionary<string, string> _cache = new(StringComparer.OrdinalIgnoreCase);
    string? _domainSid;
    string? _domainDn;
    DateTime _lastClear = DateTime.UtcNow;

    public void Annotate(AuditEntry e)
    {
        if (DateTime.UtcNow - _lastClear > TimeSpan.FromHours(1)) { _cache.Clear(); _lastClear = DateTime.UtcNow; }
        try
        {
            e.OldDisplay = Value(e.Attribute, e.OldValue);
            e.NewDisplay = Value(e.Attribute, e.NewValue);
            if (e.TargetClass.Equals("groupPolicyContainer", StringComparison.OrdinalIgnoreCase))
                e.TargetDisplay = GpoName(e.TargetDn);
        }
        catch { /* display only: never fail a query because of a lookup */ }
    }

    string? Value(string attr, string raw)
    {
        if (raw.Length == 0) return null;
        var vals = raw.Split('\n');
        var shown = vals.Select(v => One(attr, v.Trim())).ToList();
        return shown.SequenceEqual(vals.Select(v => v.Trim())) ? null : string.Join("\n", shown);
    }

    string One(string attr, string v)
    {
        switch (attr.ToLowerInvariant())
        {
            case "primarygroupid":
                return int.TryParse(v, out var rid) && DomainSid() is { } ds ? $"{Name(ds + "-" + rid) ?? "RID " + rid} ({v})" : v;
            case "useraccountcontrol":
                return long.TryParse(v, out var uac) ? $"{Flags(uac, Uac)} ({v})" : v;
            case "grouptype":
                return int.TryParse(v, out var gt) ? $"{GroupType(gt)} ({v})" : v;
            case "msds-supportedencryptiontypes":
                return long.TryParse(v, out var et) ? $"{Flags(et, Enc)} ({v})" : v;
            case "gplink":
                return GpLinkRx.Replace(v, m =>
                {
                    var name = GpoName(m.Groups["dn"].Value) ?? Dn.FriendlyName(m.Groups["dn"].Value);
                    var opt = int.Parse(m.Groups["opt"].Value);
                    return $"[{name}{((opt & 1) != 0 ? ", link disabled" : "")}{((opt & 2) != 0 ? ", enforced" : "")}]";
                });
        }
        if (FileTimeAttrs.Contains(attr) && long.TryParse(v, out var ft))
        {
            if (ft == 0 || ft == long.MaxValue) return attr.Equals("accountExpires", StringComparison.OrdinalIgnoreCase) ? "never" : "– (0)";
            if (attr.Equals("pwdLastSet", StringComparison.OrdinalIgnoreCase) && ft == -1) return "now (-1)";
            try { return DateTime.FromFileTimeUtc(ft).ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss"); } catch { return v; }
        }
        // any SID inside a value (sIDHistory, SDDL, msDS-AllowedToActOnBehalfOfOtherIdentity as text …)
        if (v.Contains("S-1-5-"))
            return SidRx.Replace(v, m => Name(m.Value) is { } n ? $"{n} ({m.Value})" : m.Value);
        return v;
    }

    string? Name(string sid) => _cache.GetOrAdd("sid:" + sid, s =>
    {
        try { return new SecurityIdentifier(s[4..]).Translate(typeof(NTAccount)).Value; }
        catch { return ""; }
    }) is { Length: > 0 } n ? n : null;

    string? DomainSid()
    {
        if (_domainSid != null) return _domainSid;
        try
        {
            using var conn = Connect();
            var dn = DomainDn(conn);
            var r = (SearchResponse)conn.SendRequest(new SearchRequest(dn, "(objectClass=*)", SearchScope.Base, "objectSid"));
            _domainSid = new SecurityIdentifier((byte[])r.Entries[0].Attributes["objectSid"][0], 0).Value;
        }
        catch { }
        return _domainSid;
    }

    string? GpoName(string dn)
    {
        var key = "gpo:" + dn;
        var name = _cache.GetOrAdd(key, _ =>
        {
            try
            {
                using var conn = Connect();
                var target = dn;
                // target DN of a GPO, or a bare {GUID}
                if (!dn.Contains('=') && GuidRx.IsMatch(dn)) target = $"CN={GuidRx.Match(dn).Value},CN=Policies,CN=System,{DomainDn(conn)}";
                var r = (SearchResponse)conn.SendRequest(new SearchRequest(target, "(objectClass=groupPolicyContainer)", SearchScope.Base, "displayName"));
                return r.Entries.Count > 0 && r.Entries[0].Attributes["displayName"] is { Count: > 0 } a ? (string)a[0] : "";
            }
            catch { return ""; }
        });
        return name.Length > 0 ? name : null;
    }

    string DomainDn(LdapConnection conn)
    {
        if (_domainDn != null) return _domainDn;
        var r = (SearchResponse)conn.SendRequest(new SearchRequest("", "(objectClass=*)", SearchScope.Base, "defaultNamingContext"));
        return _domainDn = (string)r.Entries[0].Attributes["defaultNamingContext"][0];
    }

    static LdapConnection Connect()
    {
        var c = new LdapConnection(new LdapDirectoryIdentifier("localhost", 389)) { AuthType = AuthType.Negotiate, Timeout = TimeSpan.FromSeconds(10) };
        c.SessionOptions.Signing = true;
        c.SessionOptions.Sealing = true;
        c.Bind();
        return c;
    }

    static readonly (long bit, string name)[] Uac =
    {
        (0x2, "disabled"), (0x10, "locked"), (0x20, "no password required"), (0x80, "reversible encryption"),
        (0x200, "normal account"), (0x800, "interdomain trust"), (0x1000, "workstation"), (0x2000, "domain controller"),
        (0x10000, "password never expires"), (0x40000, "smartcard required"), (0x80000, "trusted for delegation"),
        (0x100000, "not delegated"), (0x200000, "DES only"), (0x400000, "no Kerberos pre-auth"),
        (0x800000, "password expired"), (0x1000000, "trusted to auth for delegation"),
    };

    static readonly (long bit, string name)[] Enc =
        { (0x1, "DES-CRC"), (0x2, "DES-MD5"), (0x4, "RC4"), (0x8, "AES128"), (0x10, "AES256"), (0x20, "AES256-SK") };

    static string Flags(long v, (long bit, string name)[] map)
    {
        var names = map.Where(f => (v & f.bit) != 0).Select(f => f.name).ToList();
        return names.Count == 0 ? "none" : string.Join(", ", names);
    }

    static string GroupType(int v)
    {
        var scope = (v & 0x2) != 0 ? "Global" : (v & 0x4) != 0 ? "Domain local" : (v & 0x8) != 0 ? "Universal" : (v & 0x1) != 0 ? "Built-in" : "?";
        return $"{scope} {((v & unchecked((int)0x80000000)) != 0 ? "security" : "distribution")} group";
    }
}
