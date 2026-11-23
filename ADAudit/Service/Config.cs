using System.Diagnostics;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using ADAudit.Shared;

namespace ADAudit.Service;

public sealed class GuardedGroup
{
    /// <summary>sAMAccountName or CN of the group (display name when DomainRid is set).</summary>
    public string Name { get; set; } = "FS_Admin";
    /// <summary>Well-known group by RID instead of name (512 = Domain Admins in every AD language).</summary>
    public int? DomainRid { get; set; }
    /// <summary>Alert (event log, pop-up, e-mail, viewer banner) when a member is added.</summary>
    public bool Alert { get; set; } = true;
    /// <summary>Remove the added member again after MaxMembershipMinutes.</summary>
    public bool AutoRemove { get; set; } = true;
    /// <summary>Minutes after which a newly added member is removed again.</summary>
    public int MaxMembershipMinutes { get; set; } = 60;
    /// <summary>Alerts stay open until acknowledged with a reason; acknowledged memberships do not alert again.</summary>
    public bool RequireAck { get; set; }
}

public sealed class SmtpSettings
{
    public string Host { get; set; } = "";
    public int Port { get; set; } = 25;
    public bool UseSsl { get; set; }
    public string From { get; set; } = "";
    public List<string> To { get; set; } = new();
    public string User { get; set; } = "";
    /// <summary>DPAPI (machine) encrypted, base64. Never sent to viewers.</summary>
    public string PasswordProtected { get; set; } = "";

    static readonly byte[] Entropy = Encoding.UTF8.GetBytes("ADAudit-SMTP");

    public void SetPassword(string pw) => PasswordProtected = pw.Length == 0 ? "" :
        Convert.ToBase64String(ProtectedData.Protect(Encoding.UTF8.GetBytes(pw), Entropy, DataProtectionScope.LocalMachine));

    public string GetPassword()
    {
        if (PasswordProtected.Length == 0) return "";
        try { return Encoding.UTF8.GetString(ProtectedData.Unprotect(Convert.FromBase64String(PasswordProtected), Entropy, DataProtectionScope.LocalMachine)); }
        catch { return ""; }
    }
}

public sealed class Config
{
    public int PollSeconds { get; set; } = 15;

    /// <summary>Allow the viewer on admin PCs to connect over the network (\\DC\pipe\ADAudit.v1, SMB 445, Kerberos).</summary>
    public bool AllowRemoteViewers { get; set; } = true;

    /// <summary>Extra groups (e.g. "CORP\AD-Audit-Readers") allowed to view, in addition to Administrators of the DC.</summary>
    public List<string> ViewerGroups { get; set; } = new();

    /// <summary>On first start, rebuild the last half year from AD replication metadata (see README).</summary>
    public bool ReconstructHistory { get; set; } = true;

    /// <summary>Do not record computers updating their own SPN / DNS name / OS version etc. or dynamic DNS updates.</summary>
    public bool HideSystemNoise { get; set; } = true;

    /// <summary>A change undone within this many hours counts as "reverted" (default 168 = 7 days).</summary>
    public int RevertWindowHours { get; set; } = 168;

    /// <summary>Retention in days; values below 183 (half a year) are raised to 183.</summary>
    public int RetentionDays { get; set; } = 183;

    /// <summary>Explicit list of DC FQDNs. Empty = auto-discover all DCs of the domain.</summary>
    public List<string> DomainControllers { get; set; } = new();

    /// <summary>Attributes that the system rewrites constantly and that carry no administrative change.</summary>
    public List<string> IgnoredAttributes { get; set; } = new()
    {
        "lastLogonTimestamp", "lastLogon", "logonCount", "badPwdCount", "badPasswordTime", "lockoutTime",
        "dSCorePropagationData", "msDS-LastSuccessfulInteractiveLogonTime", "msDS-LastFailedInteractiveLogonTime",
        "msDS-FailedInteractiveLogonCount", "msDS-FailedInteractiveLogonCountAtLastSuccessfulLogon",
    };

    public List<GuardedGroup> GuardedGroups { get; set; } = DefaultGroups();

    static List<GuardedGroup> DefaultGroups() => new()
    {
        new GuardedGroup { Name = "FS_Admin", Alert = true, AutoRemove = true, MaxMembershipMinutes = 60 },
        new GuardedGroup { Name = "Domain Admins", DomainRid = 512, Alert = true, AutoRemove = false, RequireAck = true },
    };

    /// <summary>Config schema version (2 = per-group rules, 3 = acknowledgment + SMTP login).</summary>
    public int ConfigVersion { get; set; } = 3;

    /// <summary>
    /// If false (default), group additions that happened before the service was first started
    /// (found while back-filling existing Security logs) only raise an alert and are not auto-removed.
    /// </summary>
    public bool EnforceGuardOnBackfill { get; set; } = false;

    /// <summary>Show a message box in every interactive session on this server when a guard alert fires.</summary>
    public bool PopupAlerts { get; set; } = true;

    public SmtpSettings? Smtp { get; set; }

    public bool ResolveSourceHostDns { get; set; } = true;

    [System.Text.Json.Serialization.JsonIgnore]
    public int EffectiveRetentionDays => Math.Max(183, RetentionDays);

    [System.Text.Json.Serialization.JsonIgnore]
    public string Sha256 { get; private set; } = "";

    public static string DataDir =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "ADAudit");

    public static string ConfigPath => Path.Combine(DataDir, "config.json");

    static readonly JsonSerializerOptions Opts = new() { WriteIndented = true, PropertyNameCaseInsensitive = true };

    public static Config Load()
    {
        Directory.CreateDirectory(DataDir);
        if (!File.Exists(ConfigPath)) WriteDefault();
        var text = File.ReadAllText(ConfigPath);
        var cfg = JsonSerializer.Deserialize<Config>(text, Opts) ?? new Config();
        bool versioned = text.Contains("\"ConfigVersion\"", StringComparison.OrdinalIgnoreCase);
        if (!versioned || cfg.ConfigVersion < 3)
        {
            // v1 → v2: keep existing rules, add "Domain Admins: alert only" by default
            if (!cfg.GuardedGroups.Any(g => g.DomainRid == 512))
                cfg.GuardedGroups.Add(new GuardedGroup { Name = "Domain Admins", DomainRid = 512, Alert = true, AutoRemove = false });
            // v2 → v3: Domain Admins alerts must be acknowledged by default
            foreach (var g in cfg.GuardedGroups.Where(g => g.DomainRid == 512)) g.RequireAck = true;
            cfg.ConfigVersion = 3;
            cfg.Save();
            text = File.ReadAllText(ConfigPath);
        }
        cfg.Sha256 = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(text)));
        return cfg;
    }

    public void Save()
    {
        var text = JsonSerializer.Serialize(this, Opts);
        var tmp = ConfigPath + ".tmp";
        File.WriteAllText(tmp, text);
        File.Move(tmp, ConfigPath, true);
        Sha256 = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(text)));
        try { SecureDataDir(); } catch { }
    }

    public static void WriteDefault()
    {
        Directory.CreateDirectory(DataDir);
        if (!File.Exists(ConfigPath))
            File.WriteAllText(ConfigPath, JsonSerializer.Serialize(new Config(), Opts));
    }

    static SecurityIdentifier System => new(WellKnownSidType.LocalSystemSid, null);
    static SecurityIdentifier Admins => new(WellKnownSidType.BuiltinAdministratorsSid, null);

    /// <summary>
    /// Data directory: SYSTEM full control, Administrators read-only (inheritance from ProgramData removed).
    /// config.json: Administrators may edit. chain.key: SYSTEM only.
    /// Re-applied at every service start, so loosened permissions get restored.
    /// </summary>
    public static void SecureDataDir()
    {
        Directory.CreateDirectory(DataDir);
        var ds = new DirectorySecurity();
        ds.SetAccessRuleProtection(true, false);
        var inherit = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;
        ds.AddAccessRule(new FileSystemAccessRule(System, FileSystemRights.FullControl, inherit, PropagationFlags.None, AccessControlType.Allow));
        ds.AddAccessRule(new FileSystemAccessRule(Admins, FileSystemRights.ReadAndExecute, inherit, PropagationFlags.None, AccessControlType.Allow));
        new DirectoryInfo(DataDir).SetAccessControl(ds);

        if (File.Exists(ConfigPath))
        {
            var fs = new FileSecurity();
            fs.SetAccessRuleProtection(true, false);
            fs.AddAccessRule(new FileSystemAccessRule(System, FileSystemRights.FullControl, AccessControlType.Allow));
            fs.AddAccessRule(new FileSystemAccessRule(Admins, FileSystemRights.Modify, AccessControlType.Allow));
            new FileInfo(ConfigPath).SetAccessControl(fs);
        }
    }

    public static void SecureSystemOnly(string file)
    {
        var fs = new FileSecurity();
        fs.SetAccessRuleProtection(true, false);
        fs.AddAccessRule(new FileSystemAccessRule(System, FileSystemRights.FullControl, AccessControlType.Allow));
        new FileInfo(file).SetAccessControl(fs);
    }
}

static class Log
{
    static readonly object Gate = new();

    public static void Info(string m) => Write("INFO ", m);
    public static void Warn(string m) => Write("WARN ", m);

    public static void Error(string m, Exception? ex = null)
    {
        Write("ERROR", ex == null ? m : $"{m}: {ex}");
        WriteEventLog($"{m}{(ex == null ? "" : ": " + ex.Message)}", EventLogEntryType.Error, 1900);
    }

    public static void WriteEventLog(string message, EventLogEntryType type, int id)
    {
        try { EventLog.WriteEntry(Proto.EventSource, message, type, id); } catch { /* source not registered */ }
    }

    static void Write(string lvl, string m)
    {
        lock (Gate)
        {
            try
            {
                if (Environment.UserInteractive) Console.WriteLine($"{DateTime.Now:HH:mm:ss} {lvl} {m}");
                var dir = Path.Combine(Config.DataDir, "logs");
                Directory.CreateDirectory(dir);
                var f = Path.Combine(dir, "service.log");
                if (File.Exists(f) && new FileInfo(f).Length > 10 * 1024 * 1024) File.Move(f, f + ".1", true);
                File.AppendAllText(f, $"{DateTime.Now:yyyy-MM-dd HH:mm:ss.fff} {lvl} {m}\r\n");
            }
            catch { }
        }
    }
}
