using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace ADAudit.Shared;

public static class Cat
{
    public const string Modify = "Modify", Create = "Create", Delete = "Delete", Move = "Move", Restore = "Restore",
        Password = "Password", Lockout = "Lockout", Policy = "Policy", Tamper = "Tamper", Guard = "Guard", Service = "Service";

    public static readonly string[] All = { Modify, Create, Delete, Move, Restore, Password, Lockout, Policy, Tamper, Guard, Service };

    public static string Color(string c) => c switch
    {
        Modify => "#58A6FF",
        Create => "#3FB950",
        Delete => "#F85149",
        Move => "#A371F7",
        Restore => "#56D364",
        Password => "#D29922",
        Lockout => "#DB6D28",
        Policy => "#F778BA",
        Tamper => "#FF3B3B",
        Guard => "#FF7B72",
        _ => "#8B949E",
    };
}

/// <summary>One immutable audit trail record.</summary>
public sealed class AuditEntry
{
    public long Id { get; set; }
    public string SourceKey { get; set; } = "";
    public DateTime TimeUtc { get; set; }
    public string Dc { get; set; } = "";
    public int EventId { get; set; }
    public string Category { get; set; } = "";
    public string Action { get; set; } = "";
    public string Actor { get; set; } = "";
    public string ActorSid { get; set; } = "";
    public string LogonId { get; set; } = "";
    public string SourceHost { get; set; } = "";
    public string SourceIp { get; set; } = "";
    public string TargetDn { get; set; } = "";
    public string TargetGuid { get; set; } = "";
    public string TargetClass { get; set; } = "";
    public string Attribute { get; set; } = "";
    /// <summary>Previous value(s) / removed values (newline separated).</summary>
    public string OldValue { get; set; } = "";
    /// <summary>New value(s) / added values (newline separated).</summary>
    public string NewValue { get; set; } = "";
    public string Details { get; set; } = "";
    public string CorrelationId { get; set; } = "";
    public string PrevHash { get; set; } = "";
    public string Hash { get; set; } = "";

    // Revert links (stored in a separate append-only table, not part of the hashed record)
    public long? RevertedById { get; set; }
    public DateTime? RevertedAtUtc { get; set; }
    public string? RevertedByActor { get; set; }
    public long? RevertsId { get; set; }
    public DateTime? RevertsTimeUtc { get; set; }
    public string? LinkKind { get; set; }

    // Readable versions of raw values (resolved by the service when shown; not stored, not hashed)
    public string? OldDisplay { get; set; }
    public string? NewDisplay { get; set; }
    public string? TargetDisplay { get; set; }

    [JsonIgnore] public string OldShown => OldDisplay ?? OldValue;
    [JsonIgnore] public string NewShown => NewDisplay ?? NewValue;
    /// <summary>Same value before and after (e.g. ADUC re-writing primaryGroupID) – not a real change.</summary>
    [JsonIgnore] public bool IsNoOp => Category == Cat.Modify && OldValue.Length > 0 && SameSet(OldValue, NewValue);
    public static bool SameSet(string a, string b) =>
        new HashSet<string>(a.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries), StringComparer.OrdinalIgnoreCase)
            .SetEquals(b.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries));

    /// <summary>EventId -1 = reconstructed from AD replication metadata during initialization (actor unknown).</summary>
    public const int ReconstructedEventId = -1;
    [JsonIgnore] public bool IsReconstructed => EventId == ReconstructedEventId;

    [JsonIgnore] public string WhenLocal => TimeUtc.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss");
    [JsonIgnore] public string TargetName => TargetDisplay ?? Dn.FriendlyName(TargetDn);
    [JsonIgnore] public string CategoryColor => Cat.Color(Category);
    /// <summary>"↩ undone" = this change was undone later; "↺ undoes #id" = this change undid an earlier one.</summary>
    [JsonIgnore] public string RevertBadge => RevertedById.HasValue ? "↩ undone" : RevertsId.HasValue ? $"↺ undoes #{RevertsId}" : "";
    [JsonIgnore] public string RevertColor => RevertedById.HasValue ? "#E3B341" : "#56D364";

    [JsonIgnore]
    public string Where
    {
        get
        {
            if (SourceHost.Length > 0 && SourceIp.Length > 0 && !SourceHost.Contains(SourceIp)) return $"{SourceHost} ({SourceIp})";
            return SourceHost.Length > 0 ? SourceHost : SourceIp;
        }
    }

    [JsonIgnore]
    public string Change
    {
        get
        {
            var o = Short(Dn.Display(OldShown));
            var n = Short(Dn.Display(NewShown));
            if (Attribute.Length == 0)
            {
                if (o.Length > 0 && n.Length > 0) return $"{o} → {n}";
                return n.Length > 0 ? n : o;
            }
            if (o.Length == 0 && n.Length == 0) return Attribute;
            if (o.Length == 0) return $"{Attribute}  + {n}";
            if (n.Length == 0) return $"{Attribute}  − {o}";
            return $"{Attribute}:  {o} → {n}";
        }
    }

    static string Short(string s) => s.Length > 120 ? s[..117] + "…" : s;
}

public static class Dn
{
    /// <summary>Returns the value of the first RDN ("CN=Tom Wagner,OU=..." → "Tom Wagner").</summary>
    public static string FriendlyName(string dn)
    {
        if (string.IsNullOrEmpty(dn)) return "";
        int eq = dn.IndexOf('=');
        if (eq < 0 || eq > 12) return dn;
        var sb = new StringBuilder();
        for (int k = eq + 1; k < dn.Length; k++)
        {
            char c = dn[k];
            if (c == '\\' && k + 1 < dn.Length)
            {
                // deleted objects: "name\0ADEL:guid"
                if (dn.Length > k + 3 && dn.Substring(k + 1, 3).Equals("0AD", StringComparison.OrdinalIgnoreCase)) break;
                sb.Append(dn[k + 1]); k++; continue;
            }
            if (c == ',') break;
            sb.Append(c);
        }
        return sb.ToString();
    }

    public static bool LooksLikeDn(string v) =>
        v.Length > 3 && (v.StartsWith("CN=", StringComparison.OrdinalIgnoreCase) ||
                         v.StartsWith("OU=", StringComparison.OrdinalIgnoreCase) ||
                         v.StartsWith("DC=", StringComparison.OrdinalIgnoreCase)) && v.Contains(',');

    public static string Display(string multi) =>
        string.Join(", ", multi.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(v => LooksLikeDn(v) ? FriendlyName(v) : v));
}

public sealed class QueryRequest
{
    public string? Text { get; set; }
    public DateTime? FromUtc { get; set; }
    public DateTime? ToUtc { get; set; }
    public List<string>? Categories { get; set; }
    public string? Dc { get; set; }
    public bool OnlyReverted { get; set; }
    /// <summary>Also show automatic background changes stored before the noise filter existed.</summary>
    public bool IncludeNoise { get; set; }
    public int Limit { get; set; } = 1000;
    /// <summary>Keyset paging: return entries strictly older than (BeforeTicks, BeforeId).</summary>
    public long? BeforeTicks { get; set; }
    public long? BeforeId { get; set; }
}

public sealed class QueryResult
{
    public List<AuditEntry> Items { get; set; } = new();
    public long TotalMatches { get; set; }
}

public sealed class DcStatus
{
    public string Name { get; set; } = "";
    public string Fqdn { get; set; } = "";
    public bool IsLocal { get; set; }
    public bool Ok { get; set; }
    public DateTime? LastPollUtc { get; set; }
    public DateTime? LastEventUtc { get; set; }
    public string? LastError { get; set; }
    public long LastRecordId { get; set; }
}

public sealed class StatusInfo
{
    public string Host { get; set; } = "";
    public string Version { get; set; } = "";
    public DateTime ServiceStartedUtc { get; set; }
    public long TotalEntries { get; set; }
    public DateTime? OldestUtc { get; set; }
    public DateTime? NewestUtc { get; set; }
    public int RetentionDays { get; set; }
    /// <summary>"Backfill" (reading historic Security logs), "Reconstruct" (AD replication metadata) or "Live".</summary>
    public string Phase { get; set; } = "Live";
    public string? PhaseDetail { get; set; }
    /// <summary>0..1 while initializing.</summary>
    public double? PhaseProgress { get; set; }
    public double ServiceMemoryMb { get; set; }
    public double ServiceCpuSeconds { get; set; }
    /// <summary>The account the service sees for this viewer connection.</summary>
    public string? Caller { get; set; }
    public List<DcStatus> Dcs { get; set; } = new();
    public List<string> Warnings { get; set; } = new();
}

public sealed class VerifyResult
{
    public bool Ok { get; set; }
    public long Checked { get; set; }
    public long? FirstBadId { get; set; }
    public string Message { get; set; } = "";
    public DateTime VerifiedUtc { get; set; }
}

public static class GuardStatus
{
    public const string Pending = "Pending", Removed = "Removed", AlreadyRemoved = "AlreadyRemoved",
        AlertOnly = "AlertOnly", Failed = "Failed",
        /// <summary>Alert on a group that requires acknowledgment; stays visible until someone acknowledges it.</summary>
        Unacknowledged = "Unacknowledged",
        Acknowledged = "Acknowledged";
}

/// <summary>A membership someone explicitly approved (persistent until revoked).</summary>
public sealed class AckInfo
{
    public long Id { get; set; }
    public string GroupName { get; set; } = "";
    public string GroupGuid { get; set; } = "";
    public string MemberDn { get; set; } = "";
    public string MemberSid { get; set; } = "";
    public string Reason { get; set; } = "";
    public string By { get; set; } = "";
    public string FromHost { get; set; } = "";
    public DateTime AckUtc { get; set; }
    public DateTime? RevokedUtc { get; set; }
    public string? RevokedBy { get; set; }

    [JsonIgnore] public string MemberName => Dn.FriendlyName(MemberDn);
    [JsonIgnore] public string Summary => $"{By} · {AckUtc.ToLocalTime():yyyy-MM-dd HH:mm}";
}

public sealed class GuardItem
{
    public long Id { get; set; }
    public long AuditId { get; set; }
    public string GroupName { get; set; } = "";
    public string GroupDn { get; set; } = "";
    public string GroupGuid { get; set; } = "";
    public string MemberDn { get; set; } = "";
    public string MemberSid { get; set; } = "";
    public string AddedBy { get; set; } = "";
    public DateTime AddedUtc { get; set; }
    public DateTime DueUtc { get; set; }
    public string Status { get; set; } = GuardStatus.Pending;
    public DateTime? StatusUtc { get; set; }
    public string? Message { get; set; }
    public int Attempts { get; set; }
    /// <summary>The group's rule allows acknowledging this alert (filled in by the service).</summary>
    public bool Ackable { get; set; }
}

public sealed class DashboardRequest
{
    public DateTime FromUtc { get; set; }
    public DateTime ToUtc { get; set; }
    public int Buckets { get; set; } = 30;
}

public sealed class NamedCount
{
    public string Name { get; set; } = "";
    public long Count { get; set; }
}

public sealed class SeriesPoint
{
    public DateTime StartUtc { get; set; }
    /// <summary>Directory changes (modify/create/delete/move/restore).</summary>
    public long Changes { get; set; }
    /// <summary>Security events (password, lockout, policy, tamper, guard).</summary>
    public long Security { get; set; }
}

/// <summary>Similar events folded into one row: same category, action, actor and attribute.</summary>
public sealed class EventGroup
{
    public string Category { get; set; } = "";
    public string Action { get; set; } = "";
    public string Actor { get; set; } = "";
    public string Attribute { get; set; } = "";
    public long Count { get; set; }
    public long DistinctTargets { get; set; }
    public string Targets { get; set; } = "";
    public long Reverted { get; set; }
    public DateTime FirstUtc { get; set; }
    public DateTime LastUtc { get; set; }

    [JsonIgnore] public string CategoryColor => Cat.Color(Category);
    [JsonIgnore] public string CountText => Count == 1 ? "1×" : $"{Count:N0}×";
    [JsonIgnore] public string TargetText => DistinctTargets <= 1 ? Dn.Display(Targets) : $"{DistinctTargets:N0} objects · {Dn.Display(Targets)}";
    [JsonIgnore] public string Span => FirstUtc.Date == LastUtc.Date
        ? $"{LastUtc.ToLocalTime():dd.MM. HH:mm}"
        : $"{FirstUtc.ToLocalTime():dd.MM.} – {LastUtc.ToLocalTime():dd.MM.}";
    [JsonIgnore] public string RevertedText => Reverted == 0 ? "" : $"↩ {Reverted:N0}";
}

public sealed class DashboardInfo
{
    public long Total { get; set; }
    public long DirectoryChanges { get; set; }
    public long Membership { get; set; }
    public long CreatedDeleted { get; set; }
    public long Reverted { get; set; }
    public long Alerts { get; set; }
    public long SecurityEvents { get; set; }
    public long Tamper { get; set; }
    public List<SeriesPoint> Series { get; set; } = new();
    public List<NamedCount> Categories { get; set; } = new();
    public List<NamedCount> TopActors { get; set; } = new();
    public List<EventGroup> Groups { get; set; } = new();
}

/// <summary>Group alert / auto-removal rule as edited in the viewer's settings window.</summary>
public sealed class GuardRule
{
    public string Name { get; set; } = "";
    public int? DomainRid { get; set; }
    public bool Alert { get; set; } = true;
    public bool AutoRemove { get; set; }
    public int RemoveAfterMinutes { get; set; } = 60;
    /// <summary>Alerts stay open until acknowledged with a reason; acknowledged memberships do not alert again.</summary>
    public bool RequireAck { get; set; }
}

public sealed class AlertSettings
{
    public List<GuardRule> Rules { get; set; } = new();
    public bool PopupAlerts { get; set; } = true;
    public string SmtpHost { get; set; } = "";
    public int SmtpPort { get; set; } = 25;
    public bool SmtpSsl { get; set; }
    public string SmtpFrom { get; set; } = "";
    /// <summary>Comma / semicolon separated recipients.</summary>
    public string SmtpTo { get; set; } = "";
    public string SmtpUser { get; set; } = "";
    /// <summary>Only sent viewer → service, and only when changed. Never returned.</summary>
    public string? SmtpPasswordNew { get; set; }
    /// <summary>Service → viewer: a password is stored.</summary>
    public bool SmtpHasPassword { get; set; }
    public bool SmtpClearPassword { get; set; }
}

public sealed class PipeRequest
{
    public AlertSettings? Settings { get; set; }
    public DashboardRequest? Dashboard { get; set; }
    public string Op { get; set; } = "";
    public QueryRequest? Query { get; set; }
    public long? Id { get; set; }
    /// <summary>verify: recompute the complete chain instead of only the entries added since the last check.</summary>
    public bool Force { get; set; }
    /// <summary>guard-ack: the reason.</summary>
    public string? Text { get; set; }
}

public sealed class PipeResponse
{
    public bool Ok { get; set; } = true;
    public string? Error { get; set; }
    public QueryResult? Query { get; set; }
    public StatusInfo? Status { get; set; }
    public VerifyResult? Verify { get; set; }
    public List<GuardItem>? Guard { get; set; }
    public AuditEntry? Entry { get; set; }
    public DashboardInfo? Dashboard { get; set; }
    public AlertSettings? Settings { get; set; }
    public List<AckInfo>? Acks { get; set; }
    public string? Message { get; set; }
}

public static class Proto
{
    public const string PipeName = "ADAudit.v1";
    public const string ServiceName = "ADAudit";
    public const string EventSource = "ADAudit";

    public static readonly JsonSerializerOptions Json = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };
}
