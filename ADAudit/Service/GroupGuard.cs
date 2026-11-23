using System.Diagnostics;
using System.DirectoryServices;
using System.DirectoryServices.Protocols;
using System.Net.Mail;
using System.Runtime.InteropServices;
using System.Security.Principal;
using ADAudit.Shared;

namespace ADAudit.Service;

/// <summary>
/// Watches the configured groups (Settings → Group alerts). Per group: alert on every new member and/or
/// remove the member again after N minutes (e.g. a maintenance admin group that should stay empty). Default:
/// Domain Admins (RID 512, works in every AD language) = alert only, never removed.
/// Removal runs via LDAP on the local DC as SYSTEM.
/// </summary>
sealed class GroupGuard
{
    sealed record Target(string Name, string Dn, string Guid, GuardedGroup Rule);

    readonly Config _cfg;
    readonly AuditStore _store;
    readonly Engine _engine;
    readonly Dictionary<string, Target> _byGuid = new(StringComparer.OrdinalIgnoreCase);
    DateTime _lastResolve = DateTime.MinValue;
    public List<string> Warnings { get; } = new();

    public GroupGuard(Config cfg, AuditStore store, Engine engine)
    {
        _cfg = cfg;
        _store = store;
        _engine = engine;
    }

    /// <summary>Settings changed: resolve groups again on next use.</summary>
    public void Reload()
    {
        lock (_byGuid) { _byGuid.Clear(); _lastResolve = DateTime.MinValue; }
        try { ResolveGroups(); } catch (Exception ex) { Log.Error("Guard: resolve failed", ex); }
    }

    void ResolveGroups()
    {
        lock (_byGuid)
        {
            if (DateTime.UtcNow - _lastResolve < TimeSpan.FromMinutes(15) && _byGuid.Count > 0) return;
            _lastResolve = DateTime.UtcNow;
            _byGuid.Clear();
            Warnings.Clear();
            using var root = new DirectoryEntry("LDAP://RootDSE");
            var nc = (string)root.Properties["defaultNamingContext"].Value!;
            foreach (var g in _cfg.GuardedGroups.ToList())
            {
                try
                {
                    string dn, guid, name;
                    if (g.DomainRid is int rid)
                    {
                        using var dom = new DirectoryEntry("LDAP://" + nc);
                        var domSid = new SecurityIdentifier((byte[])dom.Properties["objectSid"].Value!, 0).Value;
                        using var grp = new DirectoryEntry($"LDAP://<SID={domSid}-{rid}>");
                        grp.RefreshCache(new[] { "distinguishedName", "objectGUID", "sAMAccountName" });
                        dn = (string)grp.Properties["distinguishedName"].Value!;
                        guid = new Guid((byte[])grp.Properties["objectGUID"].Value!).ToString();
                        name = (string?)grp.Properties["sAMAccountName"].Value ?? g.Name;
                    }
                    else
                    {
                        using var searchRoot = new DirectoryEntry("LDAP://" + nc);
                        using var s = new DirectorySearcher(searchRoot,
                            $"(&(objectCategory=group)(|(sAMAccountName={Esc(g.Name)})(cn={Esc(g.Name)})))",
                            new[] { "distinguishedName", "objectGUID", "sAMAccountName" });
                        var r = s.FindOne();
                        if (r == null) { Warnings.Add($"Alert group '{g.Name}' not found in AD."); continue; }
                        dn = (string)r.Properties["distinguishedName"][0];
                        guid = new Guid((byte[])r.Properties["objectGUID"][0]).ToString();
                        name = r.Properties["sAMAccountName"].Count > 0 ? (string)r.Properties["sAMAccountName"][0] : g.Name;
                    }
                    _byGuid[guid] = new Target(name, dn, guid, g);
                }
                catch (Exception ex)
                {
                    Warnings.Add($"Cannot resolve alert group '{g.Name}': {ex.Message}");
                }
            }
        }
    }

    static string Esc(string s) => s.Replace("\\", "\\5c").Replace("*", "\\2a").Replace("(", "\\28").Replace(")", "\\29");

    Target? Match(AuditEntry e)
    {
        lock (_byGuid)
        {
            if (_byGuid.TryGetValue(e.TargetGuid, out var t)) return t;
            // fallback by name (e.g. AD not reachable when resolving)
            var cn = Dn.FriendlyName(e.TargetDn);
            var g = _cfg.GuardedGroups.FirstOrDefault(x => x.DomainRid == null && x.Name.Equals(cn, StringComparison.OrdinalIgnoreCase));
            return g == null ? null : new Target(g.Name, e.TargetDn, e.TargetGuid, g);
        }
    }

    public void OnNewEntries(IEnumerable<AuditEntry> entries)
    {
        var adds = entries.Where(e => e.Category == Cat.Modify && e.EventId == 5136 &&
                                      e.Attribute.Equals("member", StringComparison.OrdinalIgnoreCase) &&
                                      e.NewValue.Length > 0).ToList();
        if (adds.Count == 0) return;
        try { ResolveGroups(); } catch (Exception ex) { Log.Error("Guard: resolve failed", ex); }

        var firstStart = DateTime.TryParse(_store.GetMeta("first_start_utc"), null,
            System.Globalization.DateTimeStyles.RoundtripKind, out var fs) ? fs : DateTime.UtcNow;

        foreach (var e in adds)
        {
            var t = Match(e);
            if (t == null || (!t.Rule.Alert && !t.Rule.AutoRemove)) continue;
            int minutes = Math.Max(1, t.Rule.MaxMembershipMinutes);
            foreach (var member in e.NewValue.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {
                bool backfill = e.TimeUtc < firstStart;
                var sid = LookupSid(member);
                var who = Dn.FriendlyName(member);

                // a membership someone acknowledged earlier: record it, but no alert and no removal
                var ack = t.Rule.RequireAck ? _store.FindAck(t.Guid, sid, member) : null;
                if (ack != null)
                {
                    var known = new GuardItem
                    {
                        AuditId = e.Id, GroupName = t.Name, GroupDn = t.Dn, GroupGuid = t.Guid, MemberDn = member, MemberSid = sid,
                        AddedBy = e.Actor, AddedUtc = e.TimeUtc, DueUtc = e.TimeUtc, Status = GuardStatus.Acknowledged,
                        Message = $"Previously acknowledged by {ack.By} on {ack.AckUtc.ToLocalTime():yyyy-MM-dd}: {ack.Reason}",
                    };
                    if (_store.AddGuard(known))
                        _engine.AppendSystem(Cat.Guard, $"Acknowledged member added to {t.Name}", t.Dn,
                            $"Trigger entry #{e.Id}\n{who} was added by {e.Actor}. No alert: membership acknowledged by {ack.By} " +
                            $"on {ack.AckUtc.ToLocalTime():yyyy-MM-dd HH:mm} – reason: {ack.Reason}", "", member);
                    continue;
                }

                bool remove = t.Rule.AutoRemove && (!backfill || _cfg.EnforceGuardOnBackfill);
                var item = new GuardItem
                {
                    AuditId = e.Id,
                    GroupName = t.Name,
                    GroupDn = t.Dn,
                    GroupGuid = t.Guid,
                    MemberDn = member,
                    MemberSid = sid,
                    AddedBy = e.Actor,
                    AddedUtc = e.TimeUtc,
                    DueUtc = e.TimeUtc.AddMinutes(minutes),
                    Status = remove ? GuardStatus.Pending : t.Rule.RequireAck ? GuardStatus.Unacknowledged : GuardStatus.AlertOnly,
                    Message = remove ? null
                        : t.Rule.RequireAck ? "Waiting for acknowledgment."
                        : !t.Rule.AutoRemove ? "Alert only – automatic removal is not configured for this group."
                        : "Added before ADAudit was installed – alert only.",
                };
                if (!_store.AddGuard(item)) continue;

                var msg = $"{who} was added to {t.Name} by {e.Actor} at {e.TimeUtc.ToLocalTime():yyyy-MM-dd HH:mm:ss} " +
                          $"(source: {(e.Where.Length > 0 ? e.Where : "unknown")}, DC {e.Dc}). " +
                          (remove ? $"The membership will be removed automatically at {item.DueUtc.ToLocalTime():HH:mm:ss}."
                                  : t.Rule.RequireAck ? "No automatic removal. Please review and acknowledge this membership in AD Audit Trail."
                                  : "No automatic removal.");

                _engine.AppendSystem(Cat.Guard, $"ALERT: member added to {t.Name}", t.Dn, $"Trigger entry #{e.Id}\n{msg}", "", member);
                if (t.Rule.Alert) Alert($"{t.Name} membership alert", msg, EventLogEntryType.Warning, 1001);
            }
        }
    }

    public void Tick()
    {
        List<GuardItem> due;
        try { due = _store.GuardItems(pendingOnly: true).Where(g => g.DueUtc <= DateTime.UtcNow).ToList(); }
        catch (Exception ex) { Log.Error("Guard: cannot read queue", ex); return; }

        // a pending removal whose group no longer has "remove" switched on in the settings is cancelled
        foreach (var g in due.ToList())
        {
            Target? t;
            lock (_byGuid) _byGuid.TryGetValue(g.GroupGuid, out t);
            var rule = t?.Rule ?? _cfg.GuardedGroups.FirstOrDefault(r => r.DomainRid == null && r.Name.Equals(g.GroupName, StringComparison.OrdinalIgnoreCase));
            if (rule is { AutoRemove: true }) continue;
            _store.UpdateGuard(g.Id, GuardStatus.AlertOnly, "Automatic removal was switched off in the settings before the deadline.", false);
            _engine.AppendSystem(Cat.Guard, $"{g.GroupName}: scheduled removal cancelled (settings)", g.GroupDn, $"Guard item {g.Id}, trigger entry #{g.AuditId}", g.MemberDn, "");
            due.Remove(g);
        }
        foreach (var g in due)
        {
            var who = Dn.FriendlyName(g.MemberDn);
            try
            {
                using var conn = new LdapConnection(new LdapDirectoryIdentifier("localhost", 389)) { AuthType = AuthType.Negotiate };
                conn.SessionOptions.Signing = true;
                conn.SessionOptions.Sealing = true;
                conn.Bind();
                var groupName = g.GroupGuid.Length > 0 ? $"<GUID={g.GroupGuid}>" : g.GroupDn;
                var value = g.MemberSid.Length > 0 ? $"<SID={g.MemberSid}>" : g.MemberDn;
                conn.SendRequest(new ModifyRequest(groupName, DirectoryAttributeOperation.Delete, "member", value));

                _store.UpdateGuard(g.Id, GuardStatus.Removed, $"Removed at {DateTime.Now:yyyy-MM-dd HH:mm:ss}", true);
                var msg = $"{who} was automatically removed from {g.GroupName} (added by {g.AddedBy} at {g.AddedUtc.ToLocalTime():HH:mm:ss}).";
                _engine.AppendSystem(Cat.Guard, $"Auto-removed member from {g.GroupName}", g.GroupDn, $"Guard item {g.Id}, trigger entry #{g.AuditId}\n{msg}", g.MemberDn, "");
                Alert($"{g.GroupName}: member removed", msg, EventLogEntryType.Information, 1002);
            }
            catch (DirectoryOperationException ex) when (ex.Response?.ResultCode is ResultCode.NoSuchAttribute or ResultCode.UnwillingToPerform or ResultCode.NoSuchObject)
            {
                _store.UpdateGuard(g.Id, GuardStatus.AlreadyRemoved, "Member was no longer in the group (removed manually or object deleted).", true);
                _engine.AppendSystem(Cat.Guard, $"{g.GroupName}: membership already gone", g.GroupDn, $"Guard item {g.Id}, trigger entry #{g.AuditId}", g.MemberDn, "");
            }
            catch (Exception ex)
            {
                bool giveUp = g.Attempts + 1 >= 20;
                _store.UpdateGuard(g.Id, giveUp ? GuardStatus.Failed : GuardStatus.Pending, ex.Message, true);
                Log.Error($"Guard: removing {g.MemberDn} from {g.GroupName} failed (attempt {g.Attempts + 1})", ex);
                if (g.Attempts == 0 || giveUp)
                {
                    var msg = $"FAILED to remove {who} from {g.GroupName}: {ex.Message}" + (giveUp ? " — giving up, remove manually!" : " — retrying.");
                    _engine.AppendSystem(Cat.Guard, $"{g.GroupName}: auto-removal failed", g.GroupDn, msg, g.MemberDn, "");
                    Alert($"{g.GroupName}: removal FAILED", msg, EventLogEntryType.Error, 1003);
                }
            }
        }
    }

    static string LookupSid(string dn)
    {
        try
        {
            using var de = new DirectoryEntry("LDAP://" + dn.Replace("/", "\\/"));
            de.RefreshCache(new[] { "objectSid" });
            if (de.Properties["objectSid"].Value is byte[] b) return new SecurityIdentifier(b, 0).Value;
        }
        catch (Exception ex) { Log.Warn($"Guard: SID lookup for {dn} failed: {ex.Message}"); }
        return "";
    }

    // ───────────────────────── alert channels ─────────────────────────

    void Alert(string title, string message, EventLogEntryType type, int eventId)
    {
        Log.Warn($"{title}: {message}");
        Log.WriteEventLog($"{title}\n\n{message}", type, eventId);
        if (_cfg.PopupAlerts) Task.Run(() => Popup(title, message));
        if (_cfg.Smtp is { Host.Length: > 0, To.Count: > 0 } smtp) Task.Run(() => Mail(smtp, title, message));
    }

    static void Mail(SmtpSettings s, string title, string message)
    {
        try { SendMail(s, title, message); }
        catch (Exception ex) { Log.Error("SMTP alert failed", ex); }
    }

    /// <summary>Sends one mail (SMTP AUTH when a user is configured; STARTTLS when TLS is on, e.g. port 587).</summary>
    public static void SendMail(SmtpSettings s, string title, string message)
    {
        using var client = new SmtpClient(s.Host, s.Port) { EnableSsl = s.UseSsl, Timeout = 20000, DeliveryMethod = SmtpDeliveryMethod.Network };
        if (s.User.Length > 0)
        {
            client.UseDefaultCredentials = false;
            client.Credentials = new System.Net.NetworkCredential(s.User, s.GetPassword());
        }
        var from = s.From.Length > 0 ? s.From : s.User;
        using var m = new MailMessage
        {
            From = new MailAddress(from, "AD Audit Trail"),
            Subject = $"[ADAudit] {title}",
            Body = message + $"\n\n— AD Audit Trail on {Environment.MachineName}, {DateTime.Now:yyyy-MM-dd HH:mm:ss}",
        };
        foreach (var to in s.To) m.To.Add(to);
        client.Send(m);
    }

    volatile string[] _temporary = Array.Empty<string>();

    /// <summary>Groups with automatic removal (should stay empty, e.g. a maintenance admin group).</summary>
    public IReadOnlyCollection<string> TemporaryGroupGuids()
    {
        if (Monitor.TryEnter(_byGuid))
        {
            try { _temporary = _byGuid.Values.Where(t => t.Rule.AutoRemove).Select(t => t.Guid).ToArray(); }
            finally { Monitor.Exit(_byGuid); }
        }
        return _temporary;
    }

    /// <summary>Current rule for a group (by GUID, else by name).</summary>
    public GuardedGroup? RuleFor(string groupGuid, string groupName)
    {
        lock (_byGuid)
            if (_byGuid.TryGetValue(groupGuid, out var t)) return t.Rule;
        return _cfg.GuardedGroups.FirstOrDefault(r => r.Name.Equals(groupName, StringComparison.OrdinalIgnoreCase));
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct WTS_SESSION_INFO { public int SessionId; public IntPtr WinStationName; public int State; }

    [DllImport("wtsapi32.dll", SetLastError = true)]
    static extern bool WTSEnumerateSessions(IntPtr server, int reserved, int version, out IntPtr info, out int count);
    [DllImport("wtsapi32.dll")] static extern void WTSFreeMemory(IntPtr p);
    [DllImport("wtsapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern bool WTSSendMessage(IntPtr server, int sessionId, string title, int titleLen, string msg, int msgLen,
        int style, int timeout, out int response, bool wait);

    /// <summary>Non-blocking message box in every active session on this server (the service itself has no desktop).</summary>
    static void Popup(string title, string message)
    {
        try
        {
            if (!WTSEnumerateSessions(IntPtr.Zero, 0, 1, out var p, out var count)) return;
            try
            {
                int size = Marshal.SizeOf<WTS_SESSION_INFO>();
                for (int i = 0; i < count; i++)
                {
                    var s = Marshal.PtrToStructure<WTS_SESSION_INFO>(p + i * size);
                    if (s.State != 0 || s.SessionId == 0) continue; // WTSActive only, skip services session
                    var t = "AD Audit – " + title;
                    WTSSendMessage(IntPtr.Zero, s.SessionId, t, t.Length * 2, message, message.Length * 2,
                        0x30 | 0x1000 /* MB_ICONWARNING | MB_SYSTEMMODAL */, 0, out _, false);
                }
            }
            finally { WTSFreeMemory(p); }
        }
        catch (Exception ex) { Log.Warn("Popup failed: " + ex.Message); }
    }
}
