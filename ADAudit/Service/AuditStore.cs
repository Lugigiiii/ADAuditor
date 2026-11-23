using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using ADAudit.Shared;
using Microsoft.Data.Sqlite;

namespace ADAudit.Service;

/// <summary>
/// Append-only, hash-chained audit store (SQLite).
///  * UPDATE on audit/links is rejected by triggers.
///  * DELETE is rejected for entries younger than 183 days (only the retention purge may remove older ones).
///  * Every entry carries HMAC(prev_hash ‖ content) so any edit/removal/reordering is detected by Verify().
/// </summary>
sealed class AuditStore : IDisposable
{
    const string Genesis = "GENESIS";
    const string Columns = "a.id,a.source_key,a.time_ticks,a.dc,a.event_id,a.category,a.action,a.actor,a.actor_sid,a.logon_id," +
                           "a.source_host,a.source_ip,a.target_dn,a.target_guid,a.target_class,a.attribute,a.old_value,a.new_value," +
                           "a.details,a.correlation_id,a.prev_hash,a.hash";

    readonly string _path;
    readonly byte[] _key;
    readonly SqliteConnection _db;
    readonly object _gate = new();
    SqliteTransaction? _tx;
    string _head;

    public AuditStore(string path, byte[] key)
    {
        _path = path;
        _key = key;
        _db = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = path, Mode = SqliteOpenMode.ReadWriteCreate, Pooling = false }.ToString());
        _db.Open();
        Exec("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA foreign_keys=OFF; PRAGMA cache_size=-4000; PRAGMA journal_size_limit=16777216;");
        Exec(Schema);
        _head = Scalar("SELECT hash FROM audit ORDER BY id DESC LIMIT 1") as string
                ?? GetMeta("chain_anchor") ?? Genesis;
        if (GetMeta("chain_anchor") == null) SetMeta("chain_anchor", Genesis);
    }

    const string Schema = """
        CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS audit(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source_key TEXT NOT NULL UNIQUE,
            time_ticks INTEGER NOT NULL,
            time_utc TEXT NOT NULL,
            dc TEXT NOT NULL, event_id INTEGER NOT NULL, category TEXT NOT NULL, action TEXT NOT NULL,
            actor TEXT NOT NULL, actor_sid TEXT NOT NULL, logon_id TEXT NOT NULL,
            source_host TEXT NOT NULL, source_ip TEXT NOT NULL,
            target_dn TEXT NOT NULL, target_guid TEXT NOT NULL, target_class TEXT NOT NULL,
            attribute TEXT NOT NULL, old_value TEXT NOT NULL, new_value TEXT NOT NULL,
            details TEXT NOT NULL, correlation_id TEXT NOT NULL,
            prev_hash TEXT NOT NULL, hash TEXT NOT NULL);
        CREATE INDEX IF NOT EXISTS ix_audit_time ON audit(time_ticks DESC, id DESC);
        CREATE INDEX IF NOT EXISTS ix_audit_target ON audit(target_guid, attribute, time_ticks);
        CREATE VIRTUAL TABLE IF NOT EXISTS audit_fts USING fts5(body, content='', contentless_delete=1, tokenize='trigram');
        CREATE TABLE IF NOT EXISTS links(
            audit_id INTEGER NOT NULL UNIQUE,
            reverts_id INTEGER NOT NULL UNIQUE,
            kind TEXT NOT NULL,
            created_utc TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS guard(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            audit_id INTEGER NOT NULL, group_name TEXT NOT NULL, group_dn TEXT NOT NULL, group_guid TEXT NOT NULL,
            member_dn TEXT NOT NULL, member_sid TEXT NOT NULL, added_by TEXT NOT NULL,
            added_ticks INTEGER NOT NULL, due_ticks INTEGER NOT NULL,
            status TEXT NOT NULL, status_ticks INTEGER, message TEXT, attempts INTEGER NOT NULL DEFAULT 0,
            UNIQUE(audit_id, member_dn));

        CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit
        BEGIN SELECT RAISE(ABORT, 'audit trail is immutable'); END;
        CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit
            WHEN julianday(old.time_utc) > julianday('now', '-183 days')
        BEGIN SELECT RAISE(ABORT, 'audit entries younger than 183 days cannot be deleted'); END;
        CREATE TRIGGER IF NOT EXISTS links_no_update BEFORE UPDATE ON links
        BEGIN SELECT RAISE(ABORT, 'revert links are immutable'); END;
        CREATE TRIGGER IF NOT EXISTS links_no_delete BEFORE DELETE ON links
            WHEN EXISTS(SELECT 1 FROM audit WHERE id = old.audit_id) AND EXISTS(SELECT 1 FROM audit WHERE id = old.reverts_id)
        BEGIN SELECT RAISE(ABORT, 'revert links are immutable'); END;
        """;

    // ───────────────────────── low level helpers ─────────────────────────

    SqliteCommand Cmd(string sql, params (string name, object? value)[] ps)
    {
        var c = _db.CreateCommand();
        c.CommandText = sql;
        c.Transaction = _tx;
        foreach (var (n, v) in ps) c.Parameters.AddWithValue(n, v ?? DBNull.Value);
        return c;
    }

    void Exec(string sql, params (string, object?)[] ps) { using var c = Cmd(sql, ps); c.ExecuteNonQuery(); }
    object? Scalar(string sql, params (string, object?)[] ps) { using var c = Cmd(sql, ps); var r = c.ExecuteScalar(); return r is DBNull ? null : r; }

    SqliteConnection OpenReader()
    {
        var c = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = _path, Mode = SqliteOpenMode.ReadOnly, Pooling = false }.ToString());
        c.Open();
        using var p = c.CreateCommand();
        p.CommandText = "PRAGMA cache_size=-2000;";
        p.ExecuteNonQuery();
        return c;
    }

    public string? GetMeta(string k) { lock (_gate) return Scalar("SELECT v FROM meta WHERE k=$k", ("$k", k)) as string; }
    public void SetMeta(string k, string v) { lock (_gate) Exec("INSERT INTO meta(k,v) VALUES($k,$v) ON CONFLICT(k) DO UPDATE SET v=excluded.v", ("$k", k), ("$v", v)); }

    public long GetBookmark(string dc) => long.TryParse(GetMeta("bm:" + dc), out var v) ? v : 0;

    // ───────────────────────── hashing ─────────────────────────

    string ComputeHash(AuditEntry e)
    {
        var s = string.Join('\u001f', e.PrevHash, e.SourceKey, e.TimeUtc.Ticks, e.Dc, e.EventId, e.Category, e.Action,
            e.Actor, e.ActorSid, e.LogonId, e.SourceHost, e.SourceIp, e.TargetDn, e.TargetGuid, e.TargetClass,
            e.Attribute, e.OldValue, e.NewValue, e.Details, e.CorrelationId);
        return Convert.ToHexString(HMACSHA256.HashData(_key, Encoding.UTF8.GetBytes(s)));
    }

    // ───────────────────────── append ─────────────────────────

    /// <summary>Appends entries (skipping duplicates by source key) and stores the bookmarks atomically.</summary>
    public List<AuditEntry> Append(IReadOnlyList<AuditEntry> entries, IDictionary<string, long>? bookmarks)
    {
        var inserted = new List<AuditEntry>();
        lock (_gate)
        {
            var head = _head;
            _tx = _db.BeginTransaction();
            try
            {
                foreach (var e in entries)
                {
                    if (Scalar("SELECT 1 FROM audit WHERE source_key=$k", ("$k", e.SourceKey)) != null) continue;
                    e.TimeUtc = DateTime.SpecifyKind(e.TimeUtc, DateTimeKind.Utc);
                    e.PrevHash = head;
                    e.Hash = ComputeHash(e);
                    Exec("""
                        INSERT INTO audit(source_key,time_ticks,time_utc,dc,event_id,category,action,actor,actor_sid,logon_id,
                          source_host,source_ip,target_dn,target_guid,target_class,attribute,old_value,new_value,details,correlation_id,prev_hash,hash)
                        VALUES($sk,$tt,$tu,$dc,$ev,$cat,$act,$actor,$sid,$lid,$sh,$sip,$tdn,$tg,$tc,$attr,$old,$new,$det,$corr,$prev,$hash)
                        """,
                        ("$sk", e.SourceKey), ("$tt", e.TimeUtc.Ticks), ("$tu", e.TimeUtc.ToString("yyyy-MM-ddTHH:mm:ss.fffZ")),
                        ("$dc", e.Dc), ("$ev", e.EventId), ("$cat", e.Category), ("$act", e.Action), ("$actor", e.Actor),
                        ("$sid", e.ActorSid), ("$lid", e.LogonId), ("$sh", e.SourceHost), ("$sip", e.SourceIp),
                        ("$tdn", e.TargetDn), ("$tg", e.TargetGuid), ("$tc", e.TargetClass), ("$attr", e.Attribute),
                        ("$old", e.OldValue), ("$new", e.NewValue), ("$det", e.Details), ("$corr", e.CorrelationId),
                        ("$prev", e.PrevHash), ("$hash", e.Hash));
                    e.Id = (long)Scalar("SELECT last_insert_rowid()")!;
                    Exec("INSERT INTO audit_fts(rowid, body) VALUES($id, $b)", ("$id", e.Id), ("$b", SearchBody(e)));
                    head = e.Hash;
                    LinkReverts(e);
                    inserted.Add(e);
                }
                if (bookmarks != null)
                    foreach (var (dc, rec) in bookmarks)
                        Exec("INSERT INTO meta(k,v) VALUES($k,$v) ON CONFLICT(k) DO UPDATE SET v=excluded.v", ("$k", "bm:" + dc), ("$v", rec.ToString()));
                _tx.Commit();
                _head = head;
            }
            catch
            {
                _tx.Rollback();
                throw;
            }
            finally
            {
                _tx.Dispose();
                _tx = null;
            }
        }
        return inserted;
    }

    static string SearchBody(AuditEntry e) => string.Join(' ', e.Actor, e.ActorSid, e.Action, e.Category, e.TargetDn, e.TargetGuid,
        e.TargetClass, e.Attribute, e.OldValue, e.NewValue, e.SourceHost, e.SourceIp, e.Dc, e.EventId, e.LogonId, e.Details);

    // ───────────────────────── revert linking ─────────────────────────

    static HashSet<string> Set(string v) =>
        new(v.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries), StringComparer.OrdinalIgnoreCase);

    bool IsReverted(long id) => Scalar("SELECT 1 FROM links WHERE reverts_id=$i", ("$i", id)) != null;
    bool IsReverting(long id) => Scalar("SELECT 1 FROM links WHERE audit_id=$i", ("$i", id)) != null;

    void AddLink(long newer, long older, string kind) =>
        Exec("INSERT OR IGNORE INTO links(audit_id,reverts_id,kind,created_utc) VALUES($a,$r,$k,$t)",
            ("$a", newer), ("$r", older), ("$k", kind), ("$t", DateTime.UtcNow.ToString("o")));

    /// <summary>
    /// Connects an entry with the earlier change it undoes (or the later change that undoes it, when events
    /// from the other DC arrive late): value added ↔ removed, A→B ↔ B→A, create ↔ delete, delete ↔ restore, move ↔ move back.
    /// </summary>
    void LinkReverts(AuditEntry e)
    {
        if (e.TargetGuid.Length == 0) return;

        if (e.Category is Cat.Create or Cat.Delete or Cat.Restore)
        {
            var (otherCat, kind, iAmNewer) = e.Category switch
            {
                Cat.Delete => (Cat.Create, "created → deleted", true),
                Cat.Restore => (Cat.Delete, "deleted → restored", true),
                _ => (Cat.Delete, "created → deleted", false),
            };
            using var c = Cmd(iAmNewer
                    ? "SELECT id FROM audit WHERE target_guid=$g AND category=$c AND time_ticks<=$t AND time_ticks>=$t-$w AND id<>$id ORDER BY time_ticks DESC LIMIT 5"
                    : "SELECT id FROM audit WHERE target_guid=$g AND category=$c AND time_ticks>=$t AND time_ticks<=$t+$w AND id<>$id ORDER BY time_ticks ASC LIMIT 5",
                ("$g", e.TargetGuid), ("$c", otherCat), ("$t", e.TimeUtc.Ticks), ("$id", e.Id), ("$w", RevertWindowTicks));
            var ids = new List<long>();
            using (var r = c.ExecuteReader()) while (r.Read()) ids.Add(r.GetInt64(0));
            foreach (var other in ids)
            {
                if (iAmNewer && !IsReverted(other) && !IsReverting(e.Id)) { AddLink(e.Id, other, kind); return; }
                if (!iAmNewer && !IsReverting(other) && !IsReverted(e.Id)) { AddLink(other, e.Id, kind); return; }
            }
            return;
        }

        if (e.Category is not (Cat.Modify or Cat.Move)) return;
        if (e.OldValue.Length == 0 && e.NewValue.Length == 0) return;
        if (e.IsNoOp) return; // same value written again: nothing to revert
        // reconstructed attribute changes only know the current value, not the previous one → never link them
        if (e.IsReconstructed && !e.Attribute.Equals("member", StringComparison.OrdinalIgnoreCase)) return;

        var myOld = Set(e.OldValue);
        var myNew = Set(e.NewValue);
        var cands = new List<(long id, long ticks, string old, string nw)>();
        using (var c = Cmd("""
            SELECT id, time_ticks, old_value, new_value FROM audit
            WHERE target_guid=$g AND attribute=$a AND category=$c AND id<>$id AND abs(time_ticks - $t) <= $w
            ORDER BY abs(time_ticks - $t) LIMIT 300
            """, ("$g", e.TargetGuid), ("$a", e.Attribute), ("$c", e.Category), ("$id", e.Id), ("$t", e.TimeUtc.Ticks), ("$w", RevertWindowTicks)))
        using (var r = c.ExecuteReader())
            while (r.Read()) cands.Add((r.GetInt64(0), r.GetInt64(1), r.GetString(2), r.GetString(3)));

        bool member = e.Attribute.Equals("member", StringComparison.OrdinalIgnoreCase);
        // groups that must stay empty (automatic removal): an addition is always a new event, only the removal undoes it
        bool oneWay = member && TemporaryGroups().Contains(e.TargetGuid);
        string kindText = member ? "membership reverted" : $"{e.Attribute} reverted";
        foreach (var cand in cands)
        {
            if (!Set(cand.nw).SetEquals(myOld) || !Set(cand.old).SetEquals(myNew)) continue;
            if (cand.ticks <= e.TimeUtc.Ticks)
            {
                if (oneWay && e.NewValue.Length > 0) continue; // e = re-addition: not an undo of the earlier removal
                if (!IsReverted(cand.id) && !IsReverting(e.Id)) { AddLink(e.Id, cand.id, kindText); return; }
            }
            else
            {
                if (oneWay && cand.nw.Length > 0) continue; // the newer one is an addition
                if (!IsReverting(cand.id) && !IsReverted(e.Id)) { AddLink(cand.id, e.Id, kindText); return; }
            }
        }
    }

    /// <summary>GUIDs of groups with automatic removal (groups that should stay empty, e.g. a maintenance admin group), supplied by the group guard.</summary>
    public Func<IReadOnlyCollection<string>> TemporaryGroups { get; set; } = () => Array.Empty<string>();

    /// <summary>SQL: the reverting entry <paramref name="x"/> is an addition to a temporary group → not a revert.</summary>
    string NotReAdd(string x)
    {
        var g = TemporaryGroups();
        return g.Count == 0 ? "1=1"
            : $"NOT ({x}.attribute='member' AND {x}.new_value<>'' AND {x}.target_guid IN ({string.Join(",", g.Select(s => $"'{s.Replace("'", "")}'"))}))";
    }

    // ───────────────────────── queries ─────────────────────────

    /// <summary>
    /// Only a change undone within this window counts as a revert (default 7 days). Re-adding someone who was
    /// removed a month ago is a new change, not an undo. Older links stored earlier are hidden by the same rule.
    /// </summary>
    public long RevertWindowTicks { get; set; } = TimeSpan.FromDays(7).Ticks;

    /// <summary>Revert links; links involving a no-op change (same value re-written) or outside the window are ignored.</summary>
    string LinkJoins => $"""
        LEFT JOIN (links rb JOIN audit rba ON rba.id = rb.audit_id
                   AND NOT (rba.category='Modify' AND rba.old_value<>'' AND rba.old_value=rba.new_value))
               ON rb.reverts_id = a.id AND NOT (a.category='Modify' AND a.old_value<>'' AND a.old_value=a.new_value)
                  AND abs(rba.time_ticks - a.time_ticks) <= {RevertWindowTicks} AND {NotReAdd("rba")}
        LEFT JOIN (links rv JOIN audit rva ON rva.id = rv.reverts_id
                   AND NOT (rva.category='Modify' AND rva.old_value<>'' AND rva.old_value=rva.new_value))
               ON rv.audit_id = a.id AND NOT (a.category='Modify' AND a.old_value<>'' AND a.old_value=a.new_value)
                  AND abs(rva.time_ticks - a.time_ticks) <= {RevertWindowTicks} AND {NotReAdd("a")}
        """;

    string SelectWithLinks => "SELECT " + Columns +
        ", rb.audit_id, rba.time_ticks, rba.actor, rv.reverts_id, rva.time_ticks, COALESCE(rb.kind, rv.kind) FROM audit a " + LinkJoins;

    static AuditEntry Read(SqliteDataReader r, bool withLinks)
    {
        var e = new AuditEntry
        {
            Id = r.GetInt64(0), SourceKey = r.GetString(1), TimeUtc = new DateTime(r.GetInt64(2), DateTimeKind.Utc),
            Dc = r.GetString(3), EventId = r.GetInt32(4), Category = r.GetString(5), Action = r.GetString(6),
            Actor = r.GetString(7), ActorSid = r.GetString(8), LogonId = r.GetString(9), SourceHost = r.GetString(10),
            SourceIp = r.GetString(11), TargetDn = r.GetString(12), TargetGuid = r.GetString(13), TargetClass = r.GetString(14),
            Attribute = r.GetString(15), OldValue = r.GetString(16), NewValue = r.GetString(17), Details = r.GetString(18),
            CorrelationId = r.GetString(19), PrevHash = r.GetString(20), Hash = r.GetString(21),
        };
        if (withLinks)
        {
            if (!r.IsDBNull(22)) e.RevertedById = r.GetInt64(22);
            if (!r.IsDBNull(23)) e.RevertedAtUtc = new DateTime(r.GetInt64(23), DateTimeKind.Utc);
            if (!r.IsDBNull(24)) e.RevertedByActor = r.GetString(24);
            if (!r.IsDBNull(25)) e.RevertsId = r.GetInt64(25);
            if (!r.IsDBNull(26)) e.RevertsTimeUtc = new DateTime(r.GetInt64(26), DateTimeKind.Utc);
            if (!r.IsDBNull(27)) e.LinkKind = r.GetString(27);
        }
        return e;
    }

    static readonly Regex TermRx = new("(-?)\"([^\"]+)\"|(-?)(\\S+)", RegexOptions.Compiled);

    const string LikeHaystack = "(a.actor||' '||a.action||' '||a.category||' '||a.target_dn||' '||a.attribute||' '||a.old_value||' '||" +
                                "a.new_value||' '||a.source_host||' '||a.source_ip||' '||a.dc||' '||a.event_id)";

    public QueryResult Query(QueryRequest q)
    {
        var where = new List<string>();
        var ps = new List<(string, object?)>();
        int n = 0;
        string P(object v) { var name = "$p" + n++; ps.Add((name, v)); return name; }

        if (q.FromUtc.HasValue) where.Add($"a.time_ticks >= {P(q.FromUtc.Value.ToUniversalTime().Ticks)}");
        if (q.ToUtc.HasValue) where.Add($"a.time_ticks <= {P(q.ToUtc.Value.ToUniversalTime().Ticks)}");
        if (!string.IsNullOrWhiteSpace(q.Dc)) where.Add($"a.dc = {P(q.Dc)}");
        if (q.Categories is { Count: > 0 })
            where.Add($"a.category IN ({string.Join(",", q.Categories.Select(c => P(c)))})");
        if (q.OnlyReverted) where.Add("(rb.audit_id IS NOT NULL OR rv.reverts_id IS NOT NULL)");
        if (!q.IncludeNoise) where.Add(Noise.Sql());

        if (!string.IsNullOrWhiteSpace(q.Text))
        {
            foreach (Match m in TermRx.Matches(q.Text))
            {
                bool neg = (m.Groups[1].Value + m.Groups[3].Value) == "-";
                var term = m.Groups[2].Success ? m.Groups[2].Value : m.Groups[4].Value;
                if (term.Length == 0) continue;
                string not = neg ? "NOT " : "";
                if (Regex.IsMatch(term, "^#\\d+$")) { where.Add($"a.id {(neg ? "<>" : "=")} {P(long.Parse(term[1..]))}"); continue; }
                if (term.Length >= 3)
                    where.Add($"a.id {not}IN (SELECT rowid FROM audit_fts WHERE audit_fts MATCH {P("\"" + term.Replace("\"", "\"\"") + "\"")})");
                else
                    where.Add($"{LikeHaystack} {not}LIKE {P("%" + term.Replace("\\", "\\\\").Replace("%", "\\%").Replace("_", "\\_") + "%")} ESCAPE '\\'");
            }
        }

        var countWhere = where.Count > 0 ? " WHERE " + string.Join(" AND ", where) : "";
        var pageWhere = new List<string>(where);
        if (q.BeforeTicks.HasValue && q.BeforeId.HasValue)
            pageWhere.Add($"(a.time_ticks < {P(q.BeforeTicks.Value)} OR (a.time_ticks = {P(q.BeforeTicks.Value)} AND a.id < {P(q.BeforeId.Value)}))");
        var w = pageWhere.Count > 0 ? " WHERE " + string.Join(" AND ", pageWhere) : "";
        int limit = Math.Clamp(q.Limit, 1, 10_000);

        using var db = OpenReader();
        var result = new QueryResult();
        using (var c = db.CreateCommand())
        {
            c.CommandText = SelectWithLinks + w + $" ORDER BY a.time_ticks DESC, a.id DESC LIMIT {limit}";
            foreach (var (pn, pv) in ps) c.Parameters.AddWithValue(pn, pv);
            using var r = c.ExecuteReader();
            while (r.Read()) result.Items.Add(Read(r, true));
        }
        using (var c = db.CreateCommand())
        {
            c.CommandText = "SELECT COUNT(*) FROM audit a " + LinkJoins + countWhere;
            foreach (var (pn, pv) in ps) c.Parameters.AddWithValue(pn, pv);
            result.TotalMatches = Convert.ToInt64(c.ExecuteScalar());
        }
        return result;
    }

    const string DirCats = "('Modify','Create','Delete','Move','Restore')";

    /// <summary>Aggregates for the dashboard: totals, time series, category split and similar events grouped.</summary>
    public DashboardInfo Dashboard(DashboardRequest r)
    {
        long from = r.FromUtc.ToUniversalTime().Ticks, to = r.ToUtc.ToUniversalTime().Ticks;
        int n = Math.Clamp(r.Buckets, 1, 400);
        long span = Math.Max(1, (to - from) / n);
        var d = new DashboardInfo();
        using var db = OpenReader();

        SqliteCommand C(string sql)
        {
            var c = db.CreateCommand();
            c.CommandText = sql;
            c.Parameters.AddWithValue("$f", from);
            c.Parameters.AddWithValue("$t", to);
            c.Parameters.AddWithValue("$s", span);
            c.Parameters.AddWithValue("$w", RevertWindowTicks);
            return c;
        }
        string W = " FROM audit a WHERE a.time_ticks BETWEEN $f AND $t AND " + Noise.Sql();

        using (var c = C($"""
            SELECT COUNT(*),
              SUM(category IN {DirCats}),
              SUM(attribute='member'),
              SUM(category IN ('Create','Delete')),
              SUM(EXISTS(SELECT 1 FROM links l JOIN audit x ON x.id=l.audit_id WHERE l.reverts_id=a.id AND NOT (x.old_value<>'' AND x.old_value=x.new_value) AND abs(x.time_ticks - a.time_ticks) <= $w AND {NotReAdd("x")})),
              SUM(category='Guard' AND action LIKE 'ALERT%'),
              SUM(category NOT IN {DirCats} AND category<>'Service'),
              SUM(category='Tamper')
            """ + W))
        using (var rd = c.ExecuteReader())
        {
            rd.Read();
            long L(int i) => rd.IsDBNull(i) ? 0 : rd.GetInt64(i);
            d.Total = L(0); d.DirectoryChanges = L(1); d.Membership = L(2); d.CreatedDeleted = L(3);
            d.Reverted = L(4); d.Alerts = L(5); d.SecurityEvents = L(6); d.Tamper = L(7);
        }

        var buckets = new SeriesPoint[n];
        for (int i = 0; i < n; i++) buckets[i] = new SeriesPoint { StartUtc = new DateTime(from + span * i, DateTimeKind.Utc) };
        using (var c = C($"SELECT (time_ticks-$f)/$s AS b, SUM(category IN {DirCats}), SUM(category NOT IN {DirCats} AND category<>'Service')" + W + " GROUP BY b"))
        using (var rd = c.ExecuteReader())
            while (rd.Read())
            {
                var b = (int)Math.Clamp(rd.GetInt64(0), 0, n - 1);
                buckets[b].Changes += rd.GetInt64(1);
                buckets[b].Security += rd.GetInt64(2);
            }
        d.Series = buckets.ToList();

        using (var c = C("SELECT category, COUNT(*)" + W + " GROUP BY category ORDER BY 2 DESC"))
        using (var rd = c.ExecuteReader())
            while (rd.Read()) d.Categories.Add(new NamedCount { Name = rd.GetString(0), Count = rd.GetInt64(1) });

        using (var c = C("SELECT actor, COUNT(*)" + W + " AND category<>'Service' GROUP BY actor ORDER BY 2 DESC LIMIT 6"))
        using (var rd = c.ExecuteReader())
            while (rd.Read()) d.TopActors.Add(new NamedCount { Name = rd.GetString(0), Count = rd.GetInt64(1) });

        using (var c = C($"""
            SELECT category, action, actor, attribute, COUNT(*), COUNT(DISTINCT target_dn),
                   MIN(target_dn) || CASE WHEN MIN(target_dn)<>MAX(target_dn) THEN char(10) || MAX(target_dn) ELSE '' END,
                   SUM(EXISTS(SELECT 1 FROM links l JOIN audit x ON x.id=l.audit_id WHERE l.reverts_id=a.id AND NOT (x.old_value<>'' AND x.old_value=x.new_value) AND abs(x.time_ticks - a.time_ticks) <= $w AND {NotReAdd("x")})),
                   MIN(time_ticks), MAX(time_ticks)
            """ + W + " GROUP BY category, action, actor, attribute ORDER BY MAX(time_ticks) DESC LIMIT 200"))
        using (var rd = c.ExecuteReader())
            while (rd.Read())
                d.Groups.Add(new EventGroup
                {
                    Category = rd.GetString(0), Action = rd.GetString(1), Actor = rd.GetString(2), Attribute = rd.GetString(3),
                    Count = rd.GetInt64(4), DistinctTargets = rd.GetInt64(5),
                    Targets = rd.IsDBNull(6) ? "" : rd.GetString(6),
                    Reverted = rd.IsDBNull(7) ? 0 : rd.GetInt64(7),
                    FirstUtc = new DateTime(rd.GetInt64(8), DateTimeKind.Utc), LastUtc = new DateTime(rd.GetInt64(9), DateTimeKind.Utc),
                });
        return d;
    }

    public AuditEntry? Get(long id)
    {
        using var db = OpenReader();
        using var c = db.CreateCommand();
        c.CommandText = SelectWithLinks + " WHERE a.id = $id";
        c.Parameters.AddWithValue("$id", id);
        using var r = c.ExecuteReader();
        return r.Read() ? Read(r, true) : null;
    }

    public (long count, DateTime? oldest, DateTime? newest) Stats()
    {
        using var db = OpenReader();
        using var c = db.CreateCommand();
        c.CommandText = "SELECT COUNT(*), MIN(time_ticks), MAX(time_ticks) FROM audit";
        using var r = c.ExecuteReader();
        r.Read();
        return (r.GetInt64(0),
            r.IsDBNull(1) ? null : new DateTime(r.GetInt64(1), DateTimeKind.Utc),
            r.IsDBNull(2) ? null : new DateTime(r.GetInt64(2), DateTimeKind.Utc));
    }

    public (long id, string hash) Head()
    {
        lock (_gate)
        {
            var id = Scalar("SELECT MAX(id) FROM audit");
            return (id == null ? 0 : Convert.ToInt64(id), _head);
        }
    }

    /// <summary>
    /// Is there already an entry describing the same change (used to avoid doubling entries that were
    /// reconstructed from AD metadata when the Security log also contained the real event)?
    /// </summary>
    public bool HasSimilar(string targetGuid, string category, string attribute, DateTime timeUtc, string? addedValue, string? removedValue)
    {
        lock (_gate)
        {
            var sql = "SELECT 1 FROM audit WHERE target_guid=$g AND category=$c AND time_ticks BETWEEN $a AND $b";
            var ps = new List<(string, object?)> { ("$g", targetGuid), ("$c", category),
                ("$a", timeUtc.AddSeconds(-10).Ticks), ("$b", timeUtc.AddSeconds(10).Ticks) };
            if (attribute.Length > 0) { sql += " AND attribute=$at"; ps.Add(("$at", attribute)); }
            if (!string.IsNullOrEmpty(addedValue)) { sql += " AND instr(lower(new_value), lower($nv)) > 0"; ps.Add(("$nv", addedValue)); }
            if (!string.IsNullOrEmpty(removedValue)) { sql += " AND instr(lower(old_value), lower($ov)) > 0"; ps.Add(("$ov", removedValue)); }
            return Scalar(sql + " LIMIT 1", ps.ToArray()) != null;
        }
    }

    /// <summary>
    /// Recomputes the HMAC chain. Incremental when <paramref name="afterId"/> / <paramref name="prevHash"/> are given
    /// (only entries added since the last check); full otherwise.
    /// </summary>
    public VerifyResult Verify(long afterId, string? prevHash, out long lastId, out string lastHash)
    {
        var res = new VerifyResult { VerifiedUtc = DateTime.UtcNow };
        using var db = OpenReader();
        string expectedPrev;
        if (afterId > 0 && prevHash != null) expectedPrev = prevHash;
        else
        {
            afterId = 0;
            using var m = db.CreateCommand();
            m.CommandText = "SELECT v FROM meta WHERE k='chain_anchor'";
            expectedPrev = m.ExecuteScalar() as string ?? Genesis;
        }
        using var c = db.CreateCommand();
        c.CommandText = "SELECT " + Columns + " FROM audit a WHERE a.id > $after ORDER BY a.id";
        c.Parameters.AddWithValue("$after", afterId);
        using var r = c.ExecuteReader();
        lastId = afterId;
        lastHash = expectedPrev;
        long prevId = afterId;
        while (r.Read())
        {
            var e = Read(r, false);
            if (prevId != 0 && e.Id != prevId + 1)
                return Fail(res, e.Id, $"Entries #{prevId + 1}–#{e.Id - 1} are missing (deleted).");
            if (e.PrevHash != expectedPrev)
                return Fail(res, e.Id, $"Entry #{e.Id} does not link to its predecessor (chain broken).");
            if (ComputeHash(e) != e.Hash)
                return Fail(res, e.Id, $"Entry #{e.Id} was modified after it was written.");
            expectedPrev = e.Hash;
            prevId = e.Id;
            res.Checked++;
        }
        lastId = prevId;
        lastHash = expectedPrev;
        res.Ok = true;
        return res;
    }

    static VerifyResult Fail(VerifyResult r, long id, string msg)
    {
        r.Ok = false; r.FirstBadId = id; r.Message = msg;
        return r;
    }

    /// <summary>Drops entries older than the retention period (never younger than 183 days; enforced by trigger too).</summary>
    public int Purge(int retentionDays)
    {
        retentionDays = Math.Max(183, retentionDays) + 1;
        var cutoff = DateTime.UtcNow.AddDays(-retentionDays).Ticks;
        lock (_gate)
        {
            var keep = Scalar("SELECT MIN(id) FROM audit WHERE time_ticks >= $c", ("$c", cutoff));
            if (keep == null) return 0;
            long firstKeep = Convert.ToInt64(keep);
            var any = Scalar("SELECT 1 FROM audit WHERE id < $k LIMIT 1", ("$k", firstKeep));
            if (any == null) return 0;
            _tx = _db.BeginTransaction();
            try
            {
                var anchor = (string)Scalar("SELECT prev_hash FROM audit WHERE id = $k", ("$k", firstKeep))!;
                Exec("DELETE FROM audit_fts WHERE rowid < $k", ("$k", firstKeep));
                using var del = Cmd("DELETE FROM audit WHERE id < $k", ("$k", firstKeep));
                int n = del.ExecuteNonQuery();
                Exec("DELETE FROM links WHERE audit_id NOT IN (SELECT id FROM audit) OR reverts_id NOT IN (SELECT id FROM audit)");
                Exec("INSERT INTO meta(k,v) VALUES('chain_anchor',$v) ON CONFLICT(k) DO UPDATE SET v=excluded.v", ("$v", anchor));
                _tx.Commit();
                return n;
            }
            catch { _tx.Rollback(); throw; }
            finally { _tx.Dispose(); _tx = null; }
        }
    }

    // ───────────────────────── guard state (mutable work queue, not the audit trail) ─────────────────────────

    public bool AddGuard(GuardItem g)
    {
        lock (_gate)
        {
            using var c = Cmd("""
                INSERT OR IGNORE INTO guard(audit_id,group_name,group_dn,group_guid,member_dn,member_sid,added_by,added_ticks,due_ticks,status,status_ticks,message)
                VALUES($a,$gn,$gd,$gg,$md,$ms,$by,$at,$dt,$st,$stt,$msg)
                """, ("$a", g.AuditId), ("$gn", g.GroupName), ("$gd", g.GroupDn), ("$gg", g.GroupGuid), ("$md", g.MemberDn),
                ("$ms", g.MemberSid), ("$by", g.AddedBy), ("$at", g.AddedUtc.Ticks), ("$dt", g.DueUtc.Ticks), ("$st", g.Status),
                ("$stt", DateTime.UtcNow.Ticks), ("$msg", g.Message));
            if (c.ExecuteNonQuery() == 0) return false;
            g.Id = (long)Scalar("SELECT last_insert_rowid()")!;
            return true;
        }
    }

    public void UpdateGuard(long id, string status, string? message, bool attempt)
    {
        lock (_gate)
            Exec("UPDATE guard SET status=$s, status_ticks=$t, message=$m, attempts=attempts+$a WHERE id=$id",
                ("$s", status), ("$t", DateTime.UtcNow.Ticks), ("$m", message), ("$a", attempt ? 1 : 0), ("$id", id));
    }

    public GuardItem? GetGuard(long id) => GuardQuery("WHERE id=$id", ("$id", id)).FirstOrDefault();

    public List<GuardItem> GuardItems(bool pendingOnly) => pendingOnly
        ? GuardQuery("WHERE status='Pending' ORDER BY due_ticks")
        : GuardQuery("WHERE status IN ('Pending','Unacknowledged','Failed') OR added_ticks > $since OR status_ticks > $since ORDER BY due_ticks",
            ("$since", DateTime.UtcNow.AddDays(-7).Ticks));

    // ───────────────────────── acknowledged memberships ─────────────────────────

    const string AckSchema = """
        CREATE TABLE IF NOT EXISTS acks(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            group_guid TEXT NOT NULL, group_name TEXT NOT NULL, member_dn TEXT NOT NULL, member_sid TEXT NOT NULL,
            reason TEXT NOT NULL, by_user TEXT NOT NULL, from_host TEXT NOT NULL, ack_ticks INTEGER NOT NULL,
            revoked_ticks INTEGER, revoked_by TEXT);
        """;

    bool _ackSchema;
    void EnsureAckSchema() { if (_ackSchema) return; Exec(AckSchema); _ackSchema = true; }

    public long AddAck(AckInfo a)
    {
        lock (_gate)
        {
            EnsureAckSchema();
            Exec("""
                INSERT INTO acks(group_guid,group_name,member_dn,member_sid,reason,by_user,from_host,ack_ticks)
                VALUES($g,$gn,$md,$ms,$r,$b,$h,$t)
                """, ("$g", a.GroupGuid), ("$gn", a.GroupName), ("$md", a.MemberDn), ("$ms", a.MemberSid),
                ("$r", a.Reason), ("$b", a.By), ("$h", a.FromHost), ("$t", DateTime.UtcNow.Ticks));
            return (long)Scalar("SELECT last_insert_rowid()")!;
        }
    }

    /// <summary>Active acknowledgment for this member in this group (matched by SID, or DN if no SID).</summary>
    public AckInfo? FindAck(string groupGuid, string memberSid, string memberDn) =>
        AckQuery("WHERE revoked_ticks IS NULL AND group_guid=$g AND ((member_sid<>'' AND member_sid=$s) OR lower(member_dn)=lower($d)) ORDER BY id DESC LIMIT 1",
            ("$g", groupGuid), ("$s", memberSid), ("$d", memberDn)).FirstOrDefault();

    public List<AckInfo> Acks(bool activeOnly) =>
        AckQuery(activeOnly ? "WHERE revoked_ticks IS NULL ORDER BY group_name, member_dn" : "ORDER BY id DESC");

    public AckInfo? GetAck(long id) => AckQuery("WHERE id=$id", ("$id", id)).FirstOrDefault();

    public void RevokeAck(long id, string by)
    {
        lock (_gate)
        {
            EnsureAckSchema();
            Exec("UPDATE acks SET revoked_ticks=$t, revoked_by=$b WHERE id=$id AND revoked_ticks IS NULL",
                ("$t", DateTime.UtcNow.Ticks), ("$b", by), ("$id", id));
        }
    }

    List<AckInfo> AckQuery(string where, params (string, object?)[] ps)
    {
        lock (_gate)
        {
            EnsureAckSchema();
            using var c = Cmd("SELECT id,group_guid,group_name,member_dn,member_sid,reason,by_user,from_host,ack_ticks,revoked_ticks,revoked_by FROM acks " + where, ps);
            using var r = c.ExecuteReader();
            var list = new List<AckInfo>();
            while (r.Read())
                list.Add(new AckInfo
                {
                    Id = r.GetInt64(0), GroupGuid = r.GetString(1), GroupName = r.GetString(2), MemberDn = r.GetString(3),
                    MemberSid = r.GetString(4), Reason = r.GetString(5), By = r.GetString(6), FromHost = r.GetString(7),
                    AckUtc = new DateTime(r.GetInt64(8), DateTimeKind.Utc),
                    RevokedUtc = r.IsDBNull(9) ? null : new DateTime(r.GetInt64(9), DateTimeKind.Utc),
                    RevokedBy = r.IsDBNull(10) ? null : r.GetString(10),
                });
            return list;
        }
    }

    List<GuardItem> GuardQuery(string where, params (string, object?)[] ps)
    {
        lock (_gate)
        {
            var sql = "SELECT id,audit_id,group_name,group_dn,group_guid,member_dn,member_sid,added_by,added_ticks,due_ticks,status,status_ticks,message,attempts FROM guard " + where;
            using var c = Cmd(sql, ps);
            using var r = c.ExecuteReader();
            var list = new List<GuardItem>();
            while (r.Read())
                list.Add(new GuardItem
                {
                    Id = r.GetInt64(0), AuditId = r.GetInt64(1), GroupName = r.GetString(2), GroupDn = r.GetString(3),
                    GroupGuid = r.GetString(4), MemberDn = r.GetString(5), MemberSid = r.GetString(6), AddedBy = r.GetString(7),
                    AddedUtc = new DateTime(r.GetInt64(8), DateTimeKind.Utc), DueUtc = new DateTime(r.GetInt64(9), DateTimeKind.Utc),
                    Status = r.GetString(10), StatusUtc = r.IsDBNull(11) ? null : new DateTime(r.GetInt64(11), DateTimeKind.Utc),
                    Message = r.IsDBNull(12) ? null : r.GetString(12), Attempts = r.GetInt32(13),
                });
            return list;
        }
    }

    public void Dispose()
    {
        lock (_gate) _db.Dispose();
    }
}
