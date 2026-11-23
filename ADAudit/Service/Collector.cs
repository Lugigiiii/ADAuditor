using System.Collections.Concurrent;
using System.Diagnostics.Eventing.Reader;
using System.Net;
using System.Text;
using System.Xml.Linq;
using ADAudit.Shared;

namespace ADAudit.Service;

/// <summary>A raw Security-log event with its EventData / UserData fields.</summary>
sealed class RawEvent
{
    public string Dc = "";
    public long RecordId;
    public int EventId;
    public DateTime TimeUtc;
    public bool Failure;
    public readonly Dictionary<string, string> Data = new(StringComparer.OrdinalIgnoreCase);

    public string D(string key) => Data.TryGetValue(key, out var v) ? v.Trim() : "";

    const long AuditFailureKeyword = 0x10000000000000;

    public static RawEvent From(EventRecord rec, string dc)
    {
        var ev = new RawEvent
        {
            Dc = dc,
            RecordId = rec.RecordId ?? 0,
            EventId = rec.Id,
            TimeUtc = (rec.TimeCreated ?? DateTime.Now).ToUniversalTime(),
            Failure = rec.Keywords.HasValue && (rec.Keywords.Value & AuditFailureKeyword) != 0,
        };
        var doc = XDocument.Parse(rec.ToXml());
        foreach (var d in doc.Descendants().Where(e => e.Name.LocalName == "Data"))
        {
            var name = (string?)d.Attribute("Name");
            if (name != null) ev.Data[name] = d.Value;
        }
        var ud = doc.Descendants().FirstOrDefault(e => e.Name.LocalName == "UserData");
        if (ud != null)
            foreach (var e in ud.Descendants().Where(e => !e.HasElements))
                ev.Data[e.Name.LocalName] = e.Value;
        return ev;
    }
}

/// <summary>One domain controller whose Security log is collected (locally or remotely).</summary>
sealed class DcSource
{
    public static readonly int[] EventIds =
    {
        5136, 5137, 5138, 5139, 5141, // directory service changes
        4723, 4724,                   // password change / reset
        4740, 4767,                   // lockout / unlock
        4719,                         // audit policy changed
        4794,                         // DSRM password set
        1102,                         // security log cleared
    };

    public string Name { get; }
    public string Fqdn { get; }
    public bool IsLocal { get; }
    public EventLogSession Session { get; }
    public DcStatus Status { get; }

    /// <summary>Back-off for unreachable DCs so they never slow down collection from the others.</summary>
    public int Failures;
    public DateTime NextRetryUtc = DateTime.MinValue;

    public DcSource(string fqdn, bool isLocal)
    {
        Fqdn = fqdn;
        Name = fqdn.Split('.')[0].ToUpperInvariant();
        IsLocal = isLocal;
        Session = isLocal ? new EventLogSession() : new EventLogSession(fqdn);
        Status = new DcStatus { Name = Name, Fqdn = fqdn, IsLocal = isLocal };
    }

    public (long oldest, long newest, long count) LogRange()
    {
        var info = Session.GetLogInformation("Security", PathType.LogName);
        long oldest = info.OldestRecordNumber ?? 0, count = info.RecordCount ?? 0;
        return (oldest, oldest + count - 1, count);
    }

    public static EventBookmark Bookmark(long recordId) =>
        new($"<BookmarkList><Bookmark Channel='Security' RecordId='{recordId}' IsCurrent='true'/></BookmarkList>");

    static readonly string IdFilter = string.Join(" or ", EventIds.Select(i => $"EventID={i}"));

    /// <summary>
    /// Reads matching events after <paramref name="lastRecordId"/>. The reader seeks directly to the bookmark,
    /// so a poll only touches records written since the last poll instead of re-scanning the whole Security log.
    /// </summary>
    public List<RawEvent> ReadSince(long lastRecordId, int max)
    {
        var list = new List<RawEvent>();
        EventLogReader reader;
        if (lastRecordId > 0)
        {
            try
            {
                reader = new EventLogReader(new EventLogQuery("Security", PathType.LogName, $"*[System[{IdFilter}]]") { Session = Session },
                    Bookmark(lastRecordId));
            }
            catch (EventLogException)
            {
                // bookmarked record no longer exists (log wrapped) → filter by record id instead (one full scan)
                reader = new EventLogReader(new EventLogQuery("Security", PathType.LogName,
                    $"*[System[({IdFilter}) and EventRecordID>{lastRecordId}]]") { Session = Session });
            }
        }
        else
        {
            reader = new EventLogReader(new EventLogQuery("Security", PathType.LogName, $"*[System[{IdFilter}]]") { Session = Session });
        }

        using (reader)
        {
            while (list.Count < max)
            {
                using var rec = reader.ReadEvent();
                if (rec == null) break;
                if ((rec.RecordId ?? 0) <= lastRecordId) continue;
                try { list.Add(RawEvent.From(rec, Name)); }
                catch (Exception ex) { Log.Warn($"{Name}: cannot parse record {rec.RecordId}: {ex.Message}"); }
            }
        }
        return list;
    }
}

/// <summary>Maps a logon session (SubjectLogonId) to the client machine via the matching 4624 logon event.</summary>
sealed class LogonResolver
{
    readonly ConcurrentDictionary<string, (string host, string ip)> _cache = new();
    readonly ConcurrentDictionary<string, string> _dns = new();
    readonly bool _dnsEnabled;

    public LogonResolver(bool dnsEnabled) => _dnsEnabled = dnsEnabled;

    public bool IsCached(string dc, string logonId) => _cache.ContainsKey(dc + "|" + logonId.ToLowerInvariant());

    public (string host, string ip) Resolve(DcSource dc, string logonId, DateTime timeUtc, long recordId)
    {
        if (string.IsNullOrEmpty(logonId) || logonId == "-" || logonId == "0x0") return ("", "");
        if (logonId.Equals("0x3e7", StringComparison.OrdinalIgnoreCase)) return ($"{dc.Name} (server itself)", "");
        if (logonId.Equals("0x3e4", StringComparison.OrdinalIgnoreCase) || logonId.Equals("0x3e5", StringComparison.OrdinalIgnoreCase))
            return ($"{dc.Name} (service)", "");

        var key = dc.Name + "|" + logonId.ToLowerInvariant();
        if (_cache.TryGetValue(key, out var hit)) return hit;
        if (_cache.Count > 50_000) _cache.Clear();

        try
        {
            // Search backwards starting at the change event itself: the logon that belongs to the session is
            // normally only seconds earlier, so only a handful of records are touched.
            var xpath = "*[System[EventID=4624] and EventData[Data[@Name='TargetLogonId']='" + logonId.ToLowerInvariant() + "']]";
            var q = new EventLogQuery("Security", PathType.LogName, xpath) { Session = dc.Session, ReverseDirection = true };
            EventLogReader reader;
            try { reader = recordId > 0 ? new EventLogReader(q, DcSource.Bookmark(recordId)) : new EventLogReader(q); }
            catch (EventLogException) { reader = new EventLogReader(q); }
            using var _ = reader;
            // If the logon event is no longer in the log, the search would scan the whole log backwards.
            // Give up after a few seconds instead ("from where" stays empty, result is cached).
            EventRecord? rec = null;
            try { rec = reader.ReadEvent(TimeSpan.FromSeconds(3)); }
            catch (EventLogException) { }
            using var __ = rec;
            (string, string) result = ("", "");
            if (rec != null)
            {
                var ev = RawEvent.From(rec, dc.Name);
                var ip = ev.D("IpAddress").Replace("::ffff:", "");
                var ws = ev.D("WorkstationName");
                var type = ev.D("LogonType");
                if (ws == "-") ws = "";
                if (ip is "-" or "" or "::1" or "127.0.0.1")
                {
                    ip = "";
                    var how = type switch { "2" => "console", "10" => "RDP", "11" => "cached", "5" => "service", _ => "local" };
                    result = (ws.Length > 0 && !ws.Equals(dc.Name, StringComparison.OrdinalIgnoreCase) ? ws : $"{dc.Name} ({how})", "");
                }
                else
                {
                    if (ws.Length == 0) ws = ReverseDns(ip);
                    if (type == "10") ws = (ws.Length > 0 ? ws : ip) + " via RDP";
                    result = (ws, ip);
                }
            }
            _cache[key] = result;
            return result;
        }
        catch (Exception ex)
        {
            Log.Warn($"{dc.Name}: logon {logonId} lookup failed: {ex.Message}");
            return ("", "");
        }
    }

    string ReverseDns(string ip)
    {
        if (!_dnsEnabled || !IPAddress.TryParse(ip, out var addr)) return "";
        return _dns.GetOrAdd(ip, _ =>
        {
            try
            {
                var task = Dns.GetHostEntryAsync(addr);
                return task.Wait(2000) ? task.Result.HostName : "";
            }
            catch { return ""; }
        });
    }
}

/// <summary>Turns raw Security events into audit entries (pairing 5136 delete/add values, resolving the source).</summary>
sealed class EntryBuilder
{
    const string ValueAdded = "%%14674", ValueDeleted = "%%14675";

    readonly HashSet<string> _ignored;
    readonly LogonResolver _logons;
    readonly Func<string, DcSource?> _dc;
    readonly bool _hideNoise;

    public EntryBuilder(Config cfg, LogonResolver logons, Func<string, DcSource?> dc)
    {
        _ignored = new HashSet<string>(cfg.IgnoredAttributes, StringComparer.OrdinalIgnoreCase);
        _hideNoise = cfg.HideSystemNoise;
        _logons = logons;
        _dc = dc;
    }

    sealed class ModGroup
    {
        public RawEvent First = null!;
        public readonly List<string> Added = new(), Removed = new();
        public readonly List<long> Records = new();
        public AuditEntry Entry = null!;
    }

    public List<AuditEntry> Build(IEnumerable<RawEvent> events)
    {
        var result = new List<AuditEntry>();
        var groups = new Dictionary<string, ModGroup>();

        foreach (var e in events)
        {
            if (e.EventId == 5136)
            {
                var attr = e.D("AttributeLDAPDisplayName");
                if (_ignored.Contains(attr)) continue;
                var key = $"{e.Dc}|{e.D("OpCorrelationID")}|{e.D("ObjectGUID")}|{attr}";
                if (!groups.TryGetValue(key, out var g))
                {
                    g = new ModGroup { First = e, Entry = Base(e) };
                    groups[key] = g;
                    result.Add(g.Entry);
                }
                var op = e.D("OperationType");
                var val = e.D("AttributeValue");
                if (op == ValueDeleted || op.Contains("Deleted", StringComparison.OrdinalIgnoreCase)) g.Removed.Add(val);
                else g.Added.Add(val);
                g.Records.Add(e.RecordId);
            }
            else
            {
                var entry = Map(e);
                if (entry != null) result.Add(entry);
            }
        }

        foreach (var g in groups.Values) FinishModify(g);
        if (_hideNoise) result.RemoveAll(Noise.IsNoise);

        // "From where" lookups get a total time budget per batch, newest entries first. During the import of
        // old events many logon events are already gone and each miss costs a log scan; those stay unresolved.
        var budget = System.Diagnostics.Stopwatch.StartNew();
        foreach (var entry in result.OrderByDescending(e => e.TimeUtc))
        {
            if (entry.SourceHost.Length > 0 || entry.LogonId.Length == 0) continue;
            if (budget.Elapsed > TimeSpan.FromSeconds(20) && !_logons.IsCached(entry.Dc, entry.LogonId)) continue;
            var dc = _dc(entry.Dc);
            if (dc == null) continue;
            var parts = entry.SourceKey.Split(':');
            long rec = parts.Length > 1 && long.TryParse(parts[1], out var r) ? r : 0;
            var (host, ip) = _logons.Resolve(dc, entry.LogonId, entry.TimeUtc, rec);
            entry.SourceHost = host;
            entry.SourceIp = ip;
        }
        return result;
    }

    static string Key(RawEvent e) => $"{e.Dc}:{e.RecordId}:{e.TimeUtc.Ticks}";

    static string Guid(string g) => g.Trim('{', '}', ' ').ToLowerInvariant();

    static AuditEntry Base(RawEvent e)
    {
        var sid = e.D("SubjectUserSid");
        var user = e.D("SubjectUserName");
        var dom = e.D("SubjectDomainName");
        string actor;
        if (sid == "S-1-5-18" || user.Length == 0 || user == "-") actor = $"SYSTEM ({e.Dc})";
        else if (user.EndsWith('$')) actor = $"{dom}\\{user} (computer)";
        else actor = dom.Length > 0 && dom != "-" ? $"{dom}\\{user}" : user;

        return new AuditEntry
        {
            SourceKey = Key(e),
            TimeUtc = e.TimeUtc,
            Dc = e.Dc,
            EventId = e.EventId,
            Actor = actor,
            ActorSid = sid,
            LogonId = e.D("SubjectLogonId"),
            TargetDn = e.D("ObjectDN"),
            TargetGuid = Guid(e.D("ObjectGUID")),
            TargetClass = e.D("ObjectClass"),
            CorrelationId = Guid(e.D("OpCorrelationID")),
            Details = Fields(e),
        };
    }

    static string Fields(RawEvent e)
    {
        var sb = new StringBuilder();
        sb.Append("EventID=").Append(e.EventId).Append("  Record=").Append(e.RecordId).Append("  DC=").Append(e.Dc).Append('\n');
        foreach (var kv in e.Data)
        {
            if (kv.Key is "AttributeValue") continue;
            sb.Append(kv.Key).Append('=').Append(kv.Value).Append('\n');
        }
        return sb.ToString().TrimEnd();
    }

    void FinishModify(ModGroup g)
    {
        var e = g.Entry;
        var attr = g.First.D("AttributeLDAPDisplayName");
        e.Category = Cat.Modify;
        e.Attribute = attr;
        e.OldValue = string.Join("\n", g.Removed);
        e.NewValue = string.Join("\n", g.Added);
        e.Details = $"Records={string.Join(",", g.Records)}\nSyntax={g.First.D("AttributeSyntaxOID")}\n" + e.Details;

        string cls = e.TargetClass;
        if (attr.Equals("member", StringComparison.OrdinalIgnoreCase))
            e.Action = g.Added.Count > 0 && g.Removed.Count == 0 ? "Member added to group"
                     : g.Removed.Count > 0 && g.Added.Count == 0 ? "Member removed from group" : "Group membership changed";
        else if (attr.Equals("userAccountControl", StringComparison.OrdinalIgnoreCase))
        {
            long.TryParse(g.Removed.FirstOrDefault(), out var o);
            long.TryParse(g.Added.FirstOrDefault(), out var n);
            e.Action = (o & 2) == 0 && (n & 2) != 0 ? "Account disabled"
                     : (o & 2) != 0 && (n & 2) == 0 ? "Account enabled" : "Account flags changed";
            e.Details = $"Old flags: {Uac(o)}\nNew flags: {Uac(n)}\n" + e.Details;
        }
        else if (attr.Equals("gPLink", StringComparison.OrdinalIgnoreCase)) e.Action = "GPO links changed";
        else if (attr.Equals("versionNumber", StringComparison.OrdinalIgnoreCase) && cls == "groupPolicyContainer") e.Action = "Group Policy edited";
        else if (attr.Equals("nTSecurityDescriptor", StringComparison.OrdinalIgnoreCase)) e.Action = "Permissions changed";
        else if (attr.Equals("servicePrincipalName", StringComparison.OrdinalIgnoreCase)) e.Action = "SPN changed";
        else if (g.Removed.Count == 0) e.Action = $"Set {attr}";
        else if (g.Added.Count == 0) e.Action = $"Cleared {attr}";
        else e.Action = $"Changed {attr}";
    }

    AuditEntry? Map(RawEvent e)
    {
        var x = Base(e);
        string fail = e.Failure ? " (FAILED)" : "";
        switch (e.EventId)
        {
            case 5137:
                x.Category = Cat.Create;
                x.Action = $"Created {x.TargetClass}";
                break;
            case 5141:
                x.Category = Cat.Delete;
                x.Action = $"Deleted {x.TargetClass}";
                break;
            case 5139:
                x.Category = Cat.Move;
                x.Action = "Moved / renamed object";
                x.Attribute = "(location)";
                x.OldValue = e.D("OldObjectDN");
                x.NewValue = e.D("NewObjectDN");
                x.TargetDn = x.NewValue;
                break;
            case 5138:
                x.Category = Cat.Restore;
                x.Action = $"Restored deleted {x.TargetClass}";
                x.OldValue = e.D("OldObjectDN");
                x.NewValue = e.D("NewObjectDN");
                x.TargetDn = x.NewValue;
                break;
            case 4723:
            case 4724:
                x.Category = Cat.Password;
                x.Action = (e.EventId == 4723 ? "Password changed by user" : "Password reset") + fail;
                x.TargetDn = $"{e.D("TargetDomainName")}\\{e.D("TargetUserName")}";
                break;
            case 4740:
                x.Category = Cat.Lockout;
                x.Action = "Account locked out";
                x.Actor = $"SYSTEM ({e.Dc})";
                x.TargetDn = e.D("TargetUserName");
                x.SourceHost = e.D("TargetDomainName"); // = caller computer name
                if (x.SourceHost.Length == 0) x.SourceHost = "(unknown caller)";
                break;
            case 4767:
                x.Category = Cat.Lockout;
                x.Action = "Account unlocked";
                x.TargetDn = $"{e.D("TargetDomainName")}\\{e.D("TargetUserName")}";
                break;
            case 4719:
                x.Category = Cat.Policy;
                x.Action = "Audit policy changed";
                x.TargetDn = $"Audit policy {e.D("SubcategoryGuid")}";
                x.NewValue = e.D("AuditPolicyChanges");
                break;
            case 4794:
                x.Category = Cat.Policy;
                x.Action = "DSRM administrator password set" + fail;
                x.TargetDn = e.Dc;
                var ws = e.D("Workstation");
                if (ws.Length > 0 && ws != "-") x.SourceHost = ws;
                break;
            case 1102:
                x.Category = Cat.Tamper;
                x.Action = "SECURITY LOG CLEARED";
                x.TargetDn = $"Security log on {e.Dc}";
                break;
            default:
                return null;
        }
        return x;
    }

    static readonly (long bit, string name)[] UacFlags =
    {
        (0x2, "ACCOUNTDISABLE"), (0x10, "LOCKOUT"), (0x20, "PASSWD_NOTREQD"), (0x80, "ENCRYPTED_TEXT_PWD_ALLOWED"),
        (0x200, "NORMAL_ACCOUNT"), (0x800, "INTERDOMAIN_TRUST"), (0x1000, "WORKSTATION_TRUST"), (0x2000, "SERVER_TRUST"),
        (0x10000, "DONT_EXPIRE_PASSWORD"), (0x40000, "SMARTCARD_REQUIRED"), (0x80000, "TRUSTED_FOR_DELEGATION"),
        (0x100000, "NOT_DELEGATED"), (0x200000, "USE_DES_KEY_ONLY"), (0x400000, "DONT_REQ_PREAUTH"),
        (0x800000, "PASSWORD_EXPIRED"), (0x1000000, "TRUSTED_TO_AUTH_FOR_DELEGATION"),
    };

    static string Uac(long v) =>
        $"{v} ({string.Join(" | ", UacFlags.Where(f => (v & f.bit) != 0).Select(f => f.name))})";
}
