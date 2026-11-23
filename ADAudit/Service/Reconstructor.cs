using System.DirectoryServices.Protocols;
using System.Globalization;
using System.Xml.Linq;
using ADAudit.Shared;

namespace ADAudit.Service;

/// <summary>
/// Initialization phase 2: rebuilds the last half year from Active Directory's own replication metadata,
/// for everything that is no longer (or never was) in a Security log:
///  • objects created            (whenCreated)
///  • objects deleted            (tombstones in "Deleted Objects", isDeleted change time, last known location)
///  • group members added/removed (msDS-ReplValueMetaData: per-value creation / deletion time)
///  • last change of every attribute (msDS-ReplAttributeMetaData: time, originating DC, version; current value)
/// AD does not store who made a change or from where, so these entries are marked "reconstructed".
/// Entries that already exist from real Security events are skipped (no doubles).
/// </summary>
sealed class Reconstructor
{
    const string Unknown = "(unknown – before ADAudit)";
    const string ShowDeletedOid = "1.2.840.113556.1.4.417";

    static readonly HashSet<string> SkipAttributes = new(StringComparer.OrdinalIgnoreCase)
    {
        // bookkeeping that changes with every write or logon / is part of creating an object
        "whenChanged", "uSNChanged", "replPropertyMetaData", "objectClass", "objectCategory", "objectGUID", "objectSid",
        "whenCreated", "uSNCreated", "instanceType", "name", "cn", "distinguishedName", "isDeleted", "lastKnownParent",
        "msDS-LastKnownRDN", "nTSecurityDescriptor", "dSCorePropagationData", "sAMAccountType", "isRecycled",
        "msDS-RevealedUsers", "msDS-NcType", "repsFrom", "repsTo", "dNSHostName", "msDFSR-ComputerReferenceBL",
        "lastLogonTimestamp", "lastLogon", "logonCount", "badPwdCount", "badPasswordTime", "lockoutTime",
        "dBCSPwd", "unicodePwd", "ntPwdHistory", "lmPwdHistory", "supplementalCredentials", "msDS-KeyVersionNumber",
        "currentValue", "priorValue", "initialAuthIncoming", "initialAuthOutgoing", "trustAuthIncoming", "trustAuthOutgoing",
    };

    readonly AuditStore _store;
    readonly Config _cfg;
    readonly CancellationToken _ct;
    readonly Action<string, double> _progress;
    readonly HashSet<string> _ignored;
    readonly Func<string, bool> _include;
    int _added, _skipped;

    public Reconstructor(AuditStore store, Config cfg, Func<string, bool> includeOriginDc, Action<string, double> progress, CancellationToken ct)
    {
        _include = includeOriginDc;
        _store = store;
        _cfg = cfg;
        _progress = progress;
        _ct = ct;
        _ignored = new HashSet<string>(cfg.IgnoredAttributes, StringComparer.OrdinalIgnoreCase);
    }

    sealed record Obj(string Dn, string Guid, string Class, DateTime WhenCreated);

    public (int added, int skipped) Run()
    {
        var cutoff = DateTime.UtcNow.AddDays(-_cfg.EffectiveRetentionDays);
        using var conn = new LdapConnection(new LdapDirectoryIdentifier("localhost", 389)) { AuthType = AuthType.Negotiate, Timeout = TimeSpan.FromMinutes(2) };
        conn.SessionOptions.Signing = true;
        conn.SessionOptions.Sealing = true;
        conn.Bind();

        var rootDse = (SearchResponse)conn.SendRequest(new SearchRequest("", "(objectClass=*)", SearchScope.Base, "defaultNamingContext"));
        var domainDn = (string)rootDse.Entries[0].Attributes["defaultNamingContext"][0];
        var gt = cutoff.ToString("yyyyMMddHHmmss.0Z", CultureInfo.InvariantCulture);

        // 1) everything that changed in the window (objects untouched for half a year have nothing to tell)
        _progress("Listing objects changed in the last half year…", 0);
        var objs = new List<Obj>();
        foreach (var e in Paged(conn, domainDn, $"(whenChanged>={gt})", SearchScope.Subtree, false, "objectGUID", "objectClass", "whenCreated"))
        {
            objs.Add(new Obj(e.DistinguishedName, GuidOf(e), LastClass(e), Time(e, "whenCreated")));
            _ct.ThrowIfCancellationRequested();
        }

        // 2) per object: creation, attribute metadata, linked-value metadata
        var batch = new List<AuditEntry>();
        for (int i = 0; i < objs.Count; i++)
        {
            _ct.ThrowIfCancellationRequested();
            var o = objs[i];
            try { ReadObject(conn, o, cutoff, batch); }
            catch (DirectoryOperationException) { /* object vanished meanwhile */ }
            if (batch.Count >= 200) Flush(batch);
            if (i % 25 == 0)
            {
                _progress($"Reconstructing AD history: {i + 1:N0} / {objs.Count:N0} objects", (double)i / Math.Max(1, objs.Count) * 0.9);
                Thread.Sleep(15); // stay lightweight on the DC
            }
        }
        Flush(batch);

        // 3) deleted objects (tombstones keep the deletion time and the last location)
        _progress("Reading deleted objects…", 0.92);
        foreach (var e in Paged(conn, $"CN=Deleted Objects,{domainDn}", $"(&(isDeleted=TRUE)(whenChanged>={gt}))", SearchScope.OneLevel, true,
                     "objectGUID", "objectClass", "msDS-LastKnownRDN", "lastKnownParent", "whenChanged", "whenCreated", "msDS-ReplAttributeMetaData"))
        {
            _ct.ThrowIfCancellationRequested();
            var guid = GuidOf(e);
            var cls = LastClass(e);
            var meta = AttrMeta(e).FirstOrDefault(m => m.Attr.Equals("isDeleted", StringComparison.OrdinalIgnoreCase));
            var when = meta?.Time ?? Time(e, "whenChanged");
            var rdn = Str(e, "msDS-LastKnownRDN");
            var parent = Str(e, "lastKnownParent");
            var origDn = rdn.Length > 0 ? $"CN={rdn},{parent}" : e.DistinguishedName;
            var created = Time(e, "whenCreated");
            if (created >= cutoff && created < when) Add(batch, NewEntry(guid, cls, origDn, created, meta?.Dc ?? "", Cat.Create, $"Created {cls}", "", "", "", "create"));
            if (when >= cutoff) Add(batch, NewEntry(guid, cls, e.DistinguishedName, when, meta?.Dc ?? "", Cat.Delete, $"Deleted {cls}", "", origDn, "", "delete"));
            if (batch.Count >= 200) Flush(batch);
        }
        Flush(batch);
        _progress("AD history reconstructed", 1);
        return (_added, _skipped);
    }

    void ReadObject(LdapConnection conn, Obj o, DateTime cutoff, List<AuditEntry> batch)
    {
        var req = new SearchRequest(o.Dn, "(objectClass=*)", SearchScope.Base, "msDS-ReplAttributeMetaData", "msDS-ReplValueMetaData");
        var resp = (SearchResponse)conn.SendRequest(req);
        if (resp.Entries.Count == 0) return;
        var e = resp.Entries[0];
        var attrMeta = AttrMeta(e).ToList();
        var createdDc = attrMeta.FirstOrDefault(m => m.Attr.Equals("objectClass", StringComparison.OrdinalIgnoreCase))?.Dc ?? "";

        if (o.WhenCreated >= cutoff)
            Add(batch, NewEntry(o.Guid, o.Class, o.Dn, o.WhenCreated, createdDc, Cat.Create, $"Created {o.Class}", "", "", "", "create"));

        // last change of each (non-linked) attribute
        var changed = attrMeta.Where(m => m.Time >= cutoff && !SkipAttributes.Contains(m.Attr) && !_ignored.Contains(m.Attr) &&
                                          !(m.Version == 1 && Math.Abs((m.Time - o.WhenCreated).TotalSeconds) < 5)).ToList();
        if (changed.Count > 0)
        {
            var current = CurrentValues(conn, o.Dn, changed.Select(m => m.Attr).ToArray());
            foreach (var m in changed)
            {
                current.TryGetValue(m.Attr, out var val);
                val ??= "";
                string action = m.Attr.ToLowerInvariant() switch
                {
                    "pwdlastset" => "Password set / reset",
                    "useraccountcontrol" => long.TryParse(val, out var uac) ? ((uac & 2) != 0 ? "Account disabled (current state)" : "Account enabled / flags changed") : "Account flags changed",
                    "gplink" => "GPO links changed",
                    "versionnumber" when o.Class == "groupPolicyContainer" => "Group Policy edited",
                    _ => $"Changed {m.Attr}",
                };
                if (m.Attr.Equals("pwdLastSet", StringComparison.OrdinalIgnoreCase)) val = "";
                var x = NewEntry(o.Guid, o.Class, o.Dn, m.Time, m.Dc, Cat.Modify, action, m.Attr, "", val, "attr");
                x.Details += $"\nAttribute version {m.Version}. Only the LAST change of this attribute is known; New value = value today.";
                Add(batch, x);
            }
        }

        // linked values (group membership etc.): exact add / remove time per value
        foreach (var v in ValueMeta(conn, o.Dn, e))
        {
            if (_ignored.Contains(v.Attr)) continue;
            bool isMember = v.Attr.Equals("member", StringComparison.OrdinalIgnoreCase);
            if (v.Created >= cutoff)
                Add(batch, NewEntry(o.Guid, o.Class, o.Dn, v.Created, v.Dc, Cat.Modify,
                    isMember ? "Member added to group" : $"Set {v.Attr}", v.Attr, "", v.Value, "add"));
            if (v.Deleted >= cutoff)
                Add(batch, NewEntry(o.Guid, o.Class, o.Dn, v.Deleted, v.Dc, Cat.Modify,
                    isMember ? "Member removed from group" : $"Cleared {v.Attr}", v.Attr, v.Value, "", "remove"));
        }
    }

    AuditEntry NewEntry(string guid, string cls, string dn, DateTime when, string dc, string cat, string action,
                        string attr, string oldV, string newV, string kind) => new()
    {
        SourceKey = $"Init:{guid}:{attr}:{kind}:{when.Ticks}:{StableHash(newV.Length > 0 ? newV : oldV)}",
        TimeUtc = when,
        Dc = dc.Length > 0 ? dc : "?",
        EventId = AuditEntry.ReconstructedEventId,
        Category = cat,
        Action = action,
        Actor = Unknown,
        SourceHost = "(unknown – reconstructed)",
        TargetDn = dn,
        TargetGuid = guid,
        TargetClass = cls,
        Attribute = attr,
        OldValue = oldV,
        NewValue = newV.Length > 4000 ? newV[..4000] + "…" : newV,
        Details = "Reconstructed from Active Directory replication metadata during initialization.\n" +
                  "AD stores when and on which DC a change originated, but not who made it or from where.",
    };

    static string StableHash(string s) =>
        Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(s)))[..12];

    void Add(List<AuditEntry> batch, AuditEntry x)
    {
        if (!_include(x.Dc)) return; // originated on a DC whose own Security log is imported first
        if (_cfg.HideSystemNoise && Noise.IsNoise(x)) return;
        bool member = x.SourceKey.Contains(":add:") || x.SourceKey.Contains(":remove:");
        bool dup = x.Category is Cat.Create or Cat.Delete
            ? _store.HasSimilar(x.TargetGuid, x.Category, "", x.TimeUtc, null, null)
            : _store.HasSimilar(x.TargetGuid, x.Category, x.Attribute, x.TimeUtc,
                member && x.NewValue.Length > 0 ? x.NewValue : null, member && x.OldValue.Length > 0 ? x.OldValue : null);
        if (dup || batch.Any(b => b.SourceKey == x.SourceKey)) { _skipped++; return; }
        batch.Add(x);
    }

    void Flush(List<AuditEntry> batch)
    {
        if (batch.Count == 0) return;
        batch.Sort((a, b) => a.TimeUtc.CompareTo(b.TimeUtc));
        _added += _store.Append(batch, null).Count;
        batch.Clear();
    }

    // ───────────────────────── LDAP helpers ─────────────────────────

    static IEnumerable<SearchResultEntry> Paged(LdapConnection conn, string baseDn, string filter, SearchScope scope, bool showDeleted, params string[] attrs)
    {
        var req = new SearchRequest(baseDn, filter, scope, attrs);
        var page = new PageResultRequestControl(500);
        req.Controls.Add(page);
        if (showDeleted) req.Controls.Add(new DirectoryControl(ShowDeletedOid, null, true, true));
        while (true)
        {
            var resp = (SearchResponse)conn.SendRequest(req);
            foreach (SearchResultEntry e in resp.Entries) yield return e;
            var prc = resp.Controls.OfType<PageResultResponseControl>().FirstOrDefault();
            if (prc == null || prc.Cookie.Length == 0) yield break;
            page.Cookie = prc.Cookie;
        }
    }

    static Dictionary<string, string> CurrentValues(LdapConnection conn, string dn, string[] attrs)
    {
        var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var resp = (SearchResponse)conn.SendRequest(new SearchRequest(dn, "(objectClass=*)", SearchScope.Base, attrs));
        if (resp.Entries.Count == 0) return result;
        foreach (DirectoryAttribute a in resp.Entries[0].Attributes.Values)
        {
            var name = a.Name.Split(';')[0];
            var vals = new List<string>();
            foreach (var v in a.GetValues(typeof(byte[])))
            {
                var b = (byte[])v;
                vals.Add(IsText(b) ? System.Text.Encoding.UTF8.GetString(b) : $"(binary, {b.Length} bytes)");
            }
            result[name] = string.Join("\n", vals);
        }
        return result;
    }

    static bool IsText(byte[] b) => b.All(x => x >= 0x20 || x is 0x09 or 0x0A or 0x0D) && b.Length < 8192;

    sealed record AttrMetaRow(string Attr, DateTime Time, string Dc, int Version);
    sealed record ValueMetaRow(string Attr, string Value, DateTime Created, DateTime Deleted, string Dc);

    static IEnumerable<AttrMetaRow> AttrMeta(SearchResultEntry e)
    {
        var a = e.Attributes["msDS-ReplAttributeMetaData"];
        if (a == null) yield break;
        foreach (string xml in a.GetValues(typeof(string)))
        {
            XElement x;
            try { x = XElement.Parse(xml.TrimEnd('\0')); } catch { continue; }
            yield return new AttrMetaRow((string?)x.Element("pszAttributeName") ?? "", Ft((string?)x.Element("ftimeLastOriginatingChange")),
                DsaToDc((string?)x.Element("pszLastOriginatingDsaDN")), int.TryParse((string?)x.Element("dwVersion"), out var v) ? v : 0);
        }
    }

    /// <summary>msDS-ReplValueMetaData, including ranged retrieval for large groups.</summary>
    static IEnumerable<ValueMetaRow> ValueMeta(LdapConnection conn, string dn, SearchResultEntry first)
    {
        var values = new List<string>();
        string? rangeAttr = null;
        foreach (string name in first.Attributes.AttributeNames)
            if (name.StartsWith("msDS-ReplValueMetaData", StringComparison.OrdinalIgnoreCase)) rangeAttr = name;
        if (rangeAttr == null) yield break;
        var attr = first.Attributes[rangeAttr];
        values.AddRange(attr.GetValues(typeof(string)).Cast<string>());
        // ";range=0-999" → fetch the rest
        while (rangeAttr.Contains(";range=", StringComparison.OrdinalIgnoreCase) && !rangeAttr.EndsWith("-*"))
        {
            var hi = int.Parse(rangeAttr[(rangeAttr.LastIndexOf('-') + 1)..]);
            var next = $"msDS-ReplValueMetaData;range={hi + 1}-*";
            var resp = (SearchResponse)conn.SendRequest(new SearchRequest(dn, "(objectClass=*)", SearchScope.Base, next));
            if (resp.Entries.Count == 0) break;
            rangeAttr = null;
            foreach (string name in resp.Entries[0].Attributes.AttributeNames)
                if (name.StartsWith("msDS-ReplValueMetaData", StringComparison.OrdinalIgnoreCase)) rangeAttr = name;
            if (rangeAttr == null) break;
            values.AddRange(resp.Entries[0].Attributes[rangeAttr].GetValues(typeof(string)).Cast<string>());
        }
        foreach (var xml in values)
        {
            XElement x;
            try { x = XElement.Parse(xml.TrimEnd('\0')); } catch { continue; }
            yield return new ValueMetaRow((string?)x.Element("pszAttributeName") ?? "", (string?)x.Element("pszObjectDn") ?? "",
                Ft((string?)x.Element("ftimeCreated")), Ft((string?)x.Element("ftimeDeleted")),
                DsaToDc((string?)x.Element("pszLastOriginatingDsaDN")));
        }
    }

    static DateTime Ft(string? s) =>
        DateTime.TryParse(s, CultureInfo.InvariantCulture, DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal, out var d) && d.Year > 1601
            ? DateTime.SpecifyKind(d, DateTimeKind.Utc) : DateTime.MinValue;

    /// <summary>"CN=NTDS Settings,CN=DC01,CN=Servers,…" → "DC01"</summary>
    static string DsaToDc(string? dsa)
    {
        if (string.IsNullOrEmpty(dsa)) return "";
        var parts = dsa.Split(',');
        return parts.Length > 1 ? Dn.FriendlyName(parts[1]).ToUpperInvariant() : "";
    }

    static string GuidOf(SearchResultEntry e) =>
        e.Attributes["objectGUID"]?[0] is byte[] b ? new Guid(b).ToString() : "";

    static string LastClass(SearchResultEntry e)
    {
        var a = e.Attributes["objectClass"];
        return a == null || a.Count == 0 ? "" : a[a.Count - 1] as string ?? System.Text.Encoding.UTF8.GetString((byte[])a[a.Count - 1]);
    }

    static string Str(SearchResultEntry e, string name)
    {
        var a = e.Attributes[name];
        if (a == null || a.Count == 0) return "";
        return a[0] as string ?? System.Text.Encoding.UTF8.GetString((byte[])a[0]);
    }

    static DateTime Time(SearchResultEntry e, string name)
    {
        var s = Str(e, name);
        return DateTime.TryParseExact(s, "yyyyMMddHHmmss.0Z", CultureInfo.InvariantCulture,
            DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal, out var d) ? DateTime.SpecifyKind(d, DateTimeKind.Utc) : DateTime.MinValue;
    }
}
