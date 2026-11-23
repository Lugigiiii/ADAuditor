using System.IO;
using System.Text;
using System.Text.Json;
using ADAudit.Shared;

namespace ADAudit.UI;

public interface IAuditSource
{
    Task<QueryResult> QueryAsync(QueryRequest q);
    Task<StatusInfo> StatusAsync();
    Task<VerifyResult> VerifyAsync(bool force);
    Task<DashboardInfo> DashboardAsync(DashboardRequest r);
    Task<List<GuardItem>> GuardAsync();
    Task<AuditEntry?> GetAsync(long id);
    Task<AlertSettings> GetSettingsAsync();
    Task<AlertSettings> SaveSettingsAsync(AlertSettings s);
    Task<string> TestMailAsync(AlertSettings s);
    Task<string> AcknowledgeAsync(long guardId, string reason);
    Task<List<AckInfo>> AcksAsync();
    Task<string> RevokeAckAsync(long ackId);
}

/// <summary>Generated sample data so the viewer can be previewed without a domain (ADAudit.exe --demo).</summary>
public sealed class DemoSource : IAuditSource
{
    readonly List<AuditEntry> _all = new();
    readonly List<GuardItem> _guard = new();

    public DemoSource()
    {
        var rnd = new Random(42);
        var now = DateTime.UtcNow;
        string[] admins = { "CORP\\adm.weber", "CORP\\adm.fischer", "CORP\\adm.novak", "CORP\\svc_idm" };
        (string host, string ip)[] hosts = { ("ADMWS01.corp.local", "10.20.1.15"), ("ADMWS02.corp.local", "10.20.1.22"), ("IDM01.corp.local", "10.20.5.10"), ("PAW03.corp.local", "10.20.1.40") };
        string[] users = { "Anna Becker", "Tom Wagner", "Lena Hoffmann", "Max Schulz", "Eva Koch", "Paul Richter", "Mia Klein", "Jonas Wolf", "Sara Neumann", "Felix Braun" };
        string[] groups = { "VPN_Users", "HR_Share_RW", "Finance_RO", "RDS_Users", "Print_Operators_L2", "SharePoint_Editors" };
        string[] attrs = { "title", "department", "telephoneNumber", "description", "manager", "physicalDeliveryOfficeName" };
        string[] depts = { "Finance", "HR", "IT Operations", "Sales", "Logistics", "Legal" };
        string[] dcs = { "DC01", "DC02" };
        long id = 1;
        var guids = users.ToDictionary(u => u, _ => Guid.NewGuid().ToString());
        var ggroups = groups.Append("Temp_Admins").ToDictionary(g => g, _ => Guid.NewGuid().ToString());

        string UserDn(string u) => $"CN={u},OU=Staff,OU=Corp,DC=corp,DC=local";
        string GroupDn(string g) => $"CN={g},OU=Groups,OU=Corp,DC=corp,DC=local";

        AuditEntry New(DateTime t, string cat, string action, string actor, int ev)
        {
            var h = hosts[rnd.Next(hosts.Length)];
            return new AuditEntry
            {
                Id = id++, TimeUtc = t, Category = cat, Action = action, Actor = actor, EventId = ev,
                Dc = dcs[rnd.Next(2)], SourceHost = actor.StartsWith("SYSTEM") ? "" : h.host, SourceIp = actor.StartsWith("SYSTEM") ? "" : h.ip,
                ActorSid = "S-1-5-21-3623811015-3361044348-30300820-" + rnd.Next(1100, 1500),
                LogonId = "0x" + rnd.Next(0x100000, 0xFFFFFF).ToString("x"),
                SourceKey = $"DC0{rnd.Next(1, 3)}:{rnd.Next(100000, 999999)}",
                Hash = Convert.ToHexString(Guid.NewGuid().ToByteArray()) + Convert.ToHexString(Guid.NewGuid().ToByteArray()),
                PrevHash = Convert.ToHexString(Guid.NewGuid().ToByteArray()) + Convert.ToHexString(Guid.NewGuid().ToByteArray()),
                Details = $"EventID={ev}\nSubjectUserName={actor.Split('\\').Last()}\nSubjectDomainName=CORP\nOpCorrelationID={{{Guid.NewGuid()}}}",
            };
        }

        void Link(AuditEntry older, AuditEntry newer, string kind)
        {
            older.RevertedById = newer.Id; older.RevertedAtUtc = newer.TimeUtc; older.RevertedByActor = newer.Actor; older.LinkKind = kind;
            newer.RevertsId = older.Id; newer.RevertsTimeUtc = older.TimeUtc; newer.LinkKind = kind;
        }

        var t0 = now.AddDays(-182);
        var t = t0;
        while (t < now.AddHours(-2))
        {
            t = t.AddMinutes(rnd.Next(60, 900));
            var actor = admins[rnd.Next(admins.Length)];
            var u = users[rnd.Next(users.Length)];
            int kind = rnd.Next(100);
            AuditEntry e;
            if (kind < 35)
            {
                var g = groups[rnd.Next(groups.Length)];
                e = New(t, Cat.Modify, "Member added to group", actor, 5136);
                e.TargetDn = GroupDn(g); e.TargetGuid = ggroups[g]; e.TargetClass = "group"; e.Attribute = "member"; e.NewValue = UserDn(u);
                _all.Add(e);
                if (rnd.Next(4) == 0)
                {
                    var r = New(t.AddMinutes(rnd.Next(2, 600)), Cat.Modify, "Member removed from group", admins[rnd.Next(admins.Length)], 5136);
                    r.TargetDn = e.TargetDn; r.TargetGuid = e.TargetGuid; r.TargetClass = "group"; r.Attribute = "member"; r.OldValue = e.NewValue;
                    _all.Add(r); Link(e, r, "membership reverted");
                }
            }
            else if (kind < 60)
            {
                var a = attrs[rnd.Next(attrs.Length)];
                e = New(t, Cat.Modify, $"Changed {a}", actor, 5136);
                e.TargetDn = UserDn(u); e.TargetGuid = guids[u]; e.TargetClass = "user"; e.Attribute = a;
                e.OldValue = a == "department" ? depts[rnd.Next(depts.Length)] : a == "telephoneNumber" ? $"+49 30 {rnd.Next(100000, 999999)}" : $"Old {a} value";
                e.NewValue = a == "department" ? depts[rnd.Next(depts.Length)] : a == "telephoneNumber" ? $"+49 30 {rnd.Next(100000, 999999)}" : $"New {a} value";
                _all.Add(e);
                if (rnd.Next(6) == 0)
                {
                    var r = New(t.AddMinutes(rnd.Next(1, 120)), Cat.Modify, $"Changed {a}", actor, 5136);
                    r.TargetDn = e.TargetDn; r.TargetGuid = e.TargetGuid; r.TargetClass = "user"; r.Attribute = a; r.OldValue = e.NewValue; r.NewValue = e.OldValue;
                    _all.Add(r); Link(e, r, $"{a} reverted");
                }
            }
            else if (kind < 68)
            {
                e = New(t, Cat.Modify, "Account disabled", actor, 5136);
                e.TargetDn = UserDn(u); e.TargetGuid = guids[u]; e.TargetClass = "user"; e.Attribute = "userAccountControl"; e.OldValue = "512"; e.NewValue = "514";
                e.Details = "Old flags: 512 (NORMAL_ACCOUNT)\nNew flags: 514 (ACCOUNTDISABLE | NORMAL_ACCOUNT)\n" + e.Details;
                _all.Add(e);
                if (rnd.Next(2) == 0)
                {
                    var r = New(t.AddMinutes(rnd.Next(5, 2000)), Cat.Modify, "Account enabled", actor, 5136);
                    r.TargetDn = e.TargetDn; r.TargetGuid = e.TargetGuid; r.TargetClass = "user"; r.Attribute = "userAccountControl"; r.OldValue = "514"; r.NewValue = "512";
                    _all.Add(r); Link(e, r, "userAccountControl reverted");
                }
            }
            else if (kind < 78)
            {
                e = New(t, Cat.Password, "Password reset", actor, 4724);
                e.TargetDn = "CORP\\" + u.ToLowerInvariant().Replace(' ', '.');
                _all.Add(e);
            }
            else if (kind < 85)
            {
                e = New(t, Cat.Lockout, "Account locked out", $"SYSTEM ({dcs[rnd.Next(2)]})", 4740);
                e.TargetDn = u.ToLowerInvariant().Replace(' ', '.'); e.SourceHost = $"CL-{rnd.Next(100, 400)}";
                _all.Add(e);
            }
            else if (kind < 90)
            {
                var name = $"Test User {rnd.Next(10, 99)}";
                e = New(t, Cat.Create, "Created user", actor, 5137);
                e.TargetDn = UserDn(name); e.TargetGuid = Guid.NewGuid().ToString(); e.TargetClass = "user";
                _all.Add(e);
                if (rnd.Next(2) == 0)
                {
                    var d = New(t.AddMinutes(rnd.Next(1, 90)), Cat.Delete, "Deleted user", actor, 5141);
                    d.TargetDn = $"CN={name}\\0ADEL:{e.TargetGuid},CN=Deleted Objects,DC=corp,DC=local"; d.TargetGuid = e.TargetGuid; d.TargetClass = "user";
                    _all.Add(d); Link(e, d, "created → deleted");
                }
            }
            else if (kind < 95)
            {
                e = New(t, Cat.Move, "Moved / renamed object", actor, 5139);
                e.Attribute = "(location)"; e.OldValue = UserDn(u); e.NewValue = $"CN={u},OU=Leavers,OU=Corp,DC=corp,DC=local"; e.TargetDn = e.NewValue;
                e.TargetGuid = guids[u]; e.TargetClass = "user";
                _all.Add(e);
            }
            else
            {
                e = New(t, Cat.Modify, "Group Policy edited", actor, 5136);
                e.TargetDn = "CN={31B2F340-016D-11D2-945F-00C04FB984F9},CN=Policies,CN=System,DC=corp,DC=local";
                e.TargetClass = "groupPolicyContainer"; e.Attribute = "versionNumber"; e.OldValue = rnd.Next(10, 90).ToString(); e.NewValue = (int.Parse(e.OldValue) + 1).ToString();
                e.TargetGuid = Guid.NewGuid().ToString();
                _all.Add(e);
            }
        }

        // Temp_Admins: one already removed by the guard, one pending
        var a1 = New(now.AddDays(-3), Cat.Modify, "Member added to group", "CORP\\adm.fischer", 5136);
        a1.TargetDn = GroupDn("Temp_Admins"); a1.TargetGuid = ggroups["Temp_Admins"]; a1.TargetClass = "group"; a1.Attribute = "member"; a1.NewValue = UserDn("Lena Hoffmann");
        var g1 = New(a1.TimeUtc.AddSeconds(12), Cat.Guard, "ALERT: member added to Temp_Admins", "ADAudit service (DC01)", 0);
        g1.TargetDn = a1.TargetDn; g1.NewValue = a1.NewValue; g1.SourceHost = "DC01 (server itself)"; g1.SourceIp = ""; g1.Dc = "DC01";
        var r1 = New(a1.TimeUtc.AddMinutes(60).AddSeconds(8), Cat.Modify, "Member removed from group", "SYSTEM (DC01)", 5136);
        r1.TargetDn = a1.TargetDn; r1.TargetGuid = a1.TargetGuid; r1.TargetClass = "group"; r1.Attribute = "member"; r1.OldValue = a1.NewValue; r1.SourceHost = "DC01 (server itself)"; r1.Dc = "DC01";
        _all.AddRange(new[] { a1, g1, r1 });
        Link(a1, r1, "membership reverted");
        _guard.Add(new GuardItem { Id = 1, AuditId = a1.Id, GroupName = "Temp_Admins", MemberDn = a1.NewValue, AddedBy = a1.Actor, AddedUtc = a1.TimeUtc, DueUtc = a1.TimeUtc.AddHours(1), Status = GuardStatus.Removed, StatusUtc = r1.TimeUtc });

        var a2 = New(now.AddMinutes(-23), Cat.Modify, "Member added to group", "CORP\\adm.novak", 5136);
        a2.TargetDn = GroupDn("Temp_Admins"); a2.TargetGuid = ggroups["Temp_Admins"]; a2.TargetClass = "group"; a2.Attribute = "member"; a2.NewValue = UserDn("Tom Wagner"); a2.Dc = "DC02";
        var g2 = New(a2.TimeUtc.AddSeconds(9), Cat.Guard, "ALERT: member added to Temp_Admins", "ADAudit service (DC01)", 0);
        g2.TargetDn = a2.TargetDn; g2.NewValue = a2.NewValue; g2.SourceHost = "DC01 (server itself)"; g2.SourceIp = ""; g2.Dc = "DC01";
        g2.Details = $"Trigger entry #{a2.Id}\nTom Wagner was added to Temp_Admins by CORP\\adm.novak. The membership will be removed automatically.";
        _all.AddRange(new[] { a2, g2 });
        _guard.Add(new GuardItem { Id = 2, AuditId = a2.Id, GroupName = "Temp_Admins", MemberDn = a2.NewValue, AddedBy = a2.Actor, AddedUtc = a2.TimeUtc, DueUtc = a2.TimeUtc.AddHours(1), Status = GuardStatus.Pending });

        var a3 = New(now.AddHours(-5), Cat.Modify, "Member added to group", "CORP\\adm.weber", 5136);
        a3.TargetDn = "CN=Domain Admins,CN=Users,DC=corp,DC=local"; a3.TargetGuid = Guid.NewGuid().ToString(); a3.TargetClass = "group"; a3.Attribute = "member"; a3.NewValue = UserDn("Jonas Wolf");
        _all.Add(a3);
        _guard.Add(new GuardItem { Id = 3, AuditId = a3.Id, GroupName = "Domain Admins", MemberDn = a3.NewValue, AddedBy = a3.Actor, AddedUtc = a3.TimeUtc, DueUtc = a3.TimeUtc, Status = GuardStatus.Unacknowledged, Ackable = true });

        var svc = New(now.AddDays(-182).AddHours(-1), Cat.Service, "Audit service started", "ADAudit service (DC01)", 0);
        svc.TargetDn = "DC01"; svc.SourceHost = "DC01 (server itself)"; svc.SourceIp = ""; svc.Dc = "DC01";
        _all.Add(svc);

        _all.Sort((x, y) => y.TimeUtc.CompareTo(x.TimeUtc));
    }

    public Task<QueryResult> QueryAsync(QueryRequest q)
    {
        IEnumerable<AuditEntry> r = _all;
        if (q.FromUtc.HasValue) r = r.Where(e => e.TimeUtc >= q.FromUtc);
        if (q.ToUtc.HasValue) r = r.Where(e => e.TimeUtc <= q.ToUtc);
        if (!string.IsNullOrEmpty(q.Dc)) r = r.Where(e => e.Dc == q.Dc);
        if (q.Categories is { Count: > 0 }) r = r.Where(e => q.Categories.Contains(e.Category));
        if (q.OnlyReverted) r = r.Where(e => e.RevertedById.HasValue || e.RevertsId.HasValue);
        if (!q.IncludeNoise) r = r.Where(e => !Noise.IsNoise(e));
        foreach (System.Text.RegularExpressions.Match m in System.Text.RegularExpressions.Regex.Matches(q.Text ?? "", "(-?)\"([^\"]+)\"|(-?)(\\S+)"))
        {
            bool neg = (m.Groups[1].Value + m.Groups[3].Value) == "-";
            var t = m.Groups[2].Success ? m.Groups[2].Value : m.Groups[4].Value;
            r = r.Where(e => Hay(e).Contains(t, StringComparison.OrdinalIgnoreCase) != neg);
        }
        var list = r.ToList();
        var page = list.AsEnumerable();
        if (q.BeforeTicks.HasValue)
            page = page.Where(e => e.TimeUtc.Ticks < q.BeforeTicks || (e.TimeUtc.Ticks == q.BeforeTicks && e.Id < q.BeforeId));
        return Task.FromResult(new QueryResult { Items = page.Take(q.Limit).ToList(), TotalMatches = list.Count });
    }

    static string Hay(AuditEntry e) =>
        string.Join(' ', e.Actor, e.Action, e.Category, e.TargetDn, e.Attribute, e.OldValue, e.NewValue, e.SourceHost, e.SourceIp, e.Dc, e.EventId, "#" + e.Id);

    readonly DateTime _demoStart = DateTime.UtcNow;

    public Task<StatusInfo> StatusAsync() => Task.FromResult(new StatusInfo
    {
        Phase = DateTime.UtcNow - _demoStart < TimeSpan.FromSeconds(40) ? "Reconstruct" : "Live",
        PhaseProgress = Math.Min(0.99, (DateTime.UtcNow - _demoStart).TotalSeconds / 40),
        PhaseDetail = $"Reconstructing AD history: {(int)(5412 * Math.Min(0.99, (DateTime.UtcNow - _demoStart).TotalSeconds / 40)):N0} / 5,412 objects",
        ServiceMemoryMb = 41.3, ServiceCpuSeconds = 12.4, Caller = "CORP\\adm.novak",
        Host = "DC01", Version = "1.0.0 (demo)", ServiceStartedUtc = DateTime.UtcNow.AddDays(-182), TotalEntries = _all.Count,
        OldestUtc = _all.Min(e => e.TimeUtc), NewestUtc = _all.Max(e => e.TimeUtc), RetentionDays = 183,
        Dcs = new()
        {
            new DcStatus { Name = "DC01", Fqdn = "DC01.corp.local", IsLocal = true, Ok = true, LastPollUtc = DateTime.UtcNow.AddSeconds(-4), LastRecordId = 18_442_190 },
            new DcStatus { Name = "DC02", Fqdn = "DC02.corp.local", Ok = true, LastPollUtc = DateTime.UtcNow.AddSeconds(-4), LastRecordId = 9_120_442 },
        },
    });

    public Task<VerifyResult> VerifyAsync(bool force) => Task.FromResult(new VerifyResult { Ok = true, Checked = _all.Count, Message = $"All {_all.Count:N0} entries intact.", VerifiedUtc = DateTime.UtcNow });
    public Task<DashboardInfo> DashboardAsync(DashboardRequest r)
    {
        var list = _all.Where(e => e.TimeUtc >= r.FromUtc && e.TimeUtc <= r.ToUtc).ToList();
        static bool IsDir(AuditEntry e) => e.Category is Cat.Modify or Cat.Create or Cat.Delete or Cat.Move or Cat.Restore;
        var d = new DashboardInfo
        {
            Total = list.Count,
            DirectoryChanges = list.Count(IsDir),
            Membership = list.Count(e => e.Attribute == "member"),
            CreatedDeleted = list.Count(e => e.Category is Cat.Create or Cat.Delete),
            Reverted = list.Count(e => e.RevertedById.HasValue),
            Alerts = list.Count(e => e.Category == Cat.Guard && e.Action.StartsWith("ALERT")),
            SecurityEvents = list.Count(e => !IsDir(e) && e.Category != Cat.Service),
            Tamper = list.Count(e => e.Category == Cat.Tamper),
        };
        int n = Math.Max(1, r.Buckets);
        var span = (r.ToUtc - r.FromUtc).Ticks / n;
        for (int i = 0; i < n; i++)
        {
            var s = r.FromUtc.AddTicks(span * i);
            var b = list.Where(e => e.TimeUtc >= s && e.TimeUtc < s.AddTicks(span)).ToList();
            d.Series.Add(new SeriesPoint { StartUtc = s, Changes = b.Count(IsDir), Security = b.Count(e => !IsDir(e) && e.Category != Cat.Service) });
        }
        d.Categories = list.GroupBy(e => e.Category).Select(g => new NamedCount { Name = g.Key, Count = g.LongCount() }).OrderByDescending(x => x.Count).ToList();
        d.TopActors = list.GroupBy(e => e.Actor).Select(g => new NamedCount { Name = g.Key, Count = g.LongCount() }).OrderByDescending(x => x.Count).Take(6).ToList();
        d.Groups = list.GroupBy(e => (e.Category, e.Action, e.Actor, e.Attribute)).Select(g => new EventGroup
        {
            Category = g.Key.Category, Action = g.Key.Action, Actor = g.Key.Actor, Attribute = g.Key.Attribute,
            Count = g.LongCount(), DistinctTargets = g.Select(x => x.TargetDn).Distinct().LongCount(),
            Targets = string.Join("\n", g.Select(x => x.TargetDn).Distinct().Take(3)),
            Reverted = g.LongCount(x => x.RevertedById.HasValue), FirstUtc = g.Min(x => x.TimeUtc), LastUtc = g.Max(x => x.TimeUtc),
        }).OrderByDescending(x => x.LastUtc).Take(200).ToList();
        return Task.FromResult(d);
    }

    public Task<List<GuardItem>> GuardAsync() => Task.FromResult(_guard.ToList());
    public Task<AuditEntry?> GetAsync(long id) => Task.FromResult(_all.FirstOrDefault(e => e.Id == id));

    AlertSettings _settings = new()
    {
        Rules = new()
        {
            new GuardRule { Name = "Temp_Admins", Alert = true, AutoRemove = true, RemoveAfterMinutes = 60 },
            new GuardRule { Name = "Domain Admins", DomainRid = 512, Alert = true, AutoRemove = false, RequireAck = true },
        },
    };
    public Task<AlertSettings> GetSettingsAsync() => Task.FromResult(_settings);
    public Task<AlertSettings> SaveSettingsAsync(AlertSettings s) { _settings = s; return Task.FromResult(s); }
    public Task<string> TestMailAsync(AlertSettings s) => Task.FromResult($"(demo) test mail would go to {s.SmtpTo}");
    readonly List<AckInfo> _acks = new();
    public Task<string> AcknowledgeAsync(long guardId, string reason)
    {
        var g = _guard.First(x => x.Id == guardId);
        g.Status = GuardStatus.Acknowledged; g.Message = $"Acknowledged by CORP\\adm.novak: {reason}"; g.StatusUtc = DateTime.UtcNow; g.Ackable = false;
        _acks.Add(new AckInfo { Id = _acks.Count + 1, GroupName = g.GroupName, MemberDn = g.MemberDn, Reason = reason, By = "CORP\\adm.novak", AckUtc = DateTime.UtcNow });
        return Task.FromResult("acknowledged");
    }
    public Task<List<AckInfo>> AcksAsync() => Task.FromResult(_acks.Where(a => a.RevokedUtc == null).ToList());
    public Task<string> RevokeAckAsync(long ackId) { var a = _acks.First(x => x.Id == ackId); a.RevokedUtc = DateTime.UtcNow; return Task.FromResult("revoked"); }
}
