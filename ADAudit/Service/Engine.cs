using System.Diagnostics;
using System.DirectoryServices.ActiveDirectory;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.ServiceProcess;
using System.Text;
using System.Text.Json;
using ADAudit.Shared;

namespace ADAudit.Service;

public sealed class AuditService : ServiceBase
{
    Engine? _engine;

    public AuditService()
    {
        ServiceName = Proto.ServiceName;
        CanStop = true;
        CanShutdown = true;
    }

    protected override void OnStart(string[] args)
    {
        _engine = new Engine();
        _engine.Start();
    }

    protected override void OnStop() => _engine?.Stop("stopped");
    protected override void OnShutdown() => _engine?.Stop("stopped (system shutdown)");
}

/// <summary>Collector loop + query endpoint. Runs inside the Windows service as LocalSystem.</summary>
public sealed class Engine
{
    const int LiveBatch = 2000, BackfillBatch = 1000;

    Config _cfg = null!;
    AuditStore _store = null!;
    LogonResolver _logons = null!;
    EntryBuilder _builder = null!;
    GroupGuard _guard = null!;
    PipeServer _pipe = null!;
    readonly Dictionary<string, DcSource> _dcs = new(StringComparer.OrdinalIgnoreCase);
    readonly CancellationTokenSource _cts = new();
    Thread? _thread;
    DateTime _started, _lastDiscovery = DateTime.MinValue, _lastMaintenance = DateTime.MinValue, _lastFullVerify = DateTime.MinValue;
    readonly List<string> _discoveryWarnings = new();
    readonly ValueResolver _resolver = new();

    // initialization state
    volatile string _phase = "Live";
    volatile string? _phaseDetail;
    double? _phaseProgress;
    readonly Dictionary<string, double> _backfill = new();

    // integrity check cache (incremental)
    readonly object _verifyGate = new();
    VerifyResult? _lastVerify;
    long _verifiedId;
    string? _verifiedHash;
    long _verifiedCount;

    public void Start()
    {
        _started = DateTime.UtcNow;
        // A guest on the DC: never compete with LSASS / NTDS for CPU or disk.
        try { Process.GetCurrentProcess().PriorityClass = ProcessPriorityClass.BelowNormal; } catch { }

        Config.SecureDataDir();
        _cfg = Config.Load();
        _store = new AuditStore(Path.Combine(Config.DataDir, "audit.db"), LoadKey())
        {
            RevertWindowTicks = TimeSpan.FromHours(Math.Clamp(_cfg.RevertWindowHours, 1, 24 * 183)).Ticks,
        };
        if (_store.GetMeta("first_start_utc") == null) _store.SetMeta("first_start_utc", _started.ToString("o"));
        _logons = new LogonResolver(_cfg.ResolveSourceHostDns);
        _builder = new EntryBuilder(_cfg, _logons, n => _dcs.TryGetValue(n, out var d) ? d : null);
        _guard = new GroupGuard(_cfg, _store, this);
        _store.TemporaryGroups = _guard.TemporaryGroupGuids;
        if (_store.GetMeta("init_done") == null) _phase = "Backfill";

        var (_, head) = _store.Head();
        AppendSystem(Cat.Service, "Audit service started", Environment.MachineName,
            $"Version {Version}\nConfig SHA-256 {_cfg.Sha256}\nChain head {head}\nRemote viewers: {(_cfg.AllowRemoteViewers ? "allowed" : "blocked")}");

        _pipe = new PipeServer(this, _cfg);
        _pipe.Start();
        _thread = new Thread(Loop) { IsBackground = true, Name = "collector", Priority = ThreadPriority.BelowNormal };
        _thread.Start();
        Log.Info("Engine started");
    }

    public void Stop(string reason = "stopped")
    {
        try { AppendSystem(Cat.Service, $"Audit service {reason}", Environment.MachineName); } catch { }
        _cts.Cancel();
        _thread?.Join(TimeSpan.FromSeconds(20));
        _recon?.Join(TimeSpan.FromSeconds(10));
        _pipe?.Stop();
        _store?.Dispose();
        Log.Info("Engine stopped");
    }

    static string Version => typeof(Engine).Assembly.GetName().Version?.ToString() ?? "1.0";

    /// <summary>HMAC key for the hash chain: random, DPAPI(machine)-encrypted, file readable by SYSTEM only.</summary>
    static byte[] LoadKey()
    {
        var path = Path.Combine(Config.DataDir, "chain.key");
        if (File.Exists(path))
            return ProtectedData.Unprotect(File.ReadAllBytes(path), Encoding.UTF8.GetBytes("ADAudit"), DataProtectionScope.LocalMachine);
        var key = RandomNumberGenerator.GetBytes(32);
        File.WriteAllBytes(path, ProtectedData.Protect(key, Encoding.UTF8.GetBytes("ADAudit"), DataProtectionScope.LocalMachine));
        Config.SecureSystemOnly(path);
        return key;
    }

    public AuditEntry AppendSystem(string category, string action, string target, string details = "", string oldValue = "", string newValue = "",
                                   string? actor = null, string? sourceHost = null)
    {
        var e = new AuditEntry
        {
            SourceKey = "ADAudit:" + Guid.NewGuid().ToString("N"),
            TimeUtc = DateTime.UtcNow,
            Dc = Environment.MachineName.ToUpperInvariant(),
            Category = category,
            Action = action,
            Actor = actor ?? $"ADAudit service ({Environment.MachineName})",
            ActorSid = actor == null ? "S-1-5-18" : "",
            SourceHost = sourceHost ?? $"{Environment.MachineName} (server itself)",
            TargetDn = target,
            OldValue = oldValue,
            NewValue = newValue,
            Details = details,
        };
        _store.Append(new[] { e }, null);
        return e;
    }

    // ───────────────────────── collector loop ─────────────────────────

    void Loop()
    {
        BeginBackgroundMode();
        _guard.Reload(); // resolve watched groups once at start (FS_Admin GUID etc.)
        while (!_cts.IsCancellationRequested)
        {
            bool more = false;
            try { more = Cycle(); }
            catch (Exception ex) { Log.Error("Collector cycle failed", ex); }

            if (!more && _phase == "Backfill") FinishBackfill();
            // the AD history import runs on its own thread: live collection and the FS_Admin timer never wait for it
            if (_phase == "Reconstruct" && _recon is not { IsAlive: true } && _store.GetMeta("init_done") == null) StartReconstruction(null);
            else if (_phase == "Live" && !more) ReconstructLateDcs();

            try { _guard.Tick(); } catch (Exception ex) { Log.Error("Guard tick failed", ex); }
            try { Maintenance(); } catch (Exception ex) { Log.Error("Maintenance failed", ex); }

            // back-fill: short breather between batches; live: normal poll interval
            var wait = more ? TimeSpan.FromMilliseconds(300) : TimeSpan.FromSeconds(Math.Clamp(_cfg.PollSeconds, 5, 300));
            _cts.Token.WaitHandle.WaitOne(wait);
        }
    }

    [DllImport("kernel32.dll")] static extern IntPtr GetCurrentThread();
    [DllImport("kernel32.dll")] static extern bool SetThreadPriority(IntPtr thread, int priority);

    /// <summary>THREAD_MODE_BACKGROUND_BEGIN: lowest CPU, I/O and memory priority for the collector thread.</summary>
    static void BeginBackgroundMode()
    {
        try { SetThreadPriority(GetCurrentThread(), 0x00010000); } catch { }
    }

    bool BackfillDone(string dc) => _store.GetMeta("bf_done:" + dc) != null;

    /// <summary>
    /// Phase 1 ends when every DC we can reach has been read completely. Unreachable DCs do not block:
    /// their log is imported whenever they become reachable, and their AD history afterwards (ReconstructLateDcs).
    /// </summary>
    void FinishBackfill()
    {
        if (_dcs.Values.Any(d => d.Status.Ok && !BackfillDone(d.Name))) return;
        if (!_dcs.Values.Any(d => BackfillDone(d.Name))) return;
        _backfill.Clear();
        if (_cfg.ReconstructHistory) _phase = "Reconstruct";
        else
        {
            _store.SetMeta("init_done", DateTime.UtcNow.ToString("o"));
            _phase = "Live";
        }
    }

    /// <summary>History of changes that originated on a DC that was unreachable during initialization.</summary>
    void ReconstructLateDcs()
    {
        if (!_cfg.ReconstructHistory || _store.GetMeta("init_done") is not { } done || done.StartsWith("failed")) return;
        var late = _dcs.Values.Where(d => BackfillDone(d.Name) && _store.GetMeta("recon_done:" + d.Name) == null)
                              .Select(d => d.Name).ToHashSet(StringComparer.OrdinalIgnoreCase);
        if (late.Count == 0) return;
        StartReconstruction(late);
    }

    Thread? _recon;

    void StartReconstruction(HashSet<string>? only)
    {
        if (_recon is { IsAlive: true }) return;
        _phase = "Reconstruct";
        _recon = new Thread(() => { BeginBackgroundMode(); Reconstruct(only); })
            { IsBackground = true, Name = "reconstruct", Priority = ThreadPriority.Lowest };
        _recon.Start();
    }

    /// <param name="only">null = initial run (all DCs whose log was fully read); otherwise only changes from these DCs.</param>
    void Reconstruct(HashSet<string>? only)
    {
        var pending = _dcs.Values.Where(d => !BackfillDone(d.Name)).Select(d => d.Name).ToHashSet(StringComparer.OrdinalIgnoreCase);
        // Changes that originated on a DC whose Security log has not been read yet are skipped for now:
        // its real events (with who / from where) come first, the metadata fills the gaps afterwards.
        Func<string, bool> include = only == null
            ? dc => !pending.Contains(dc)
            : dc => only.Contains(dc);
        var scope = only == null ? "domain" : string.Join(", ", only);
        try
        {
            AppendSystem(Cat.Service, $"Initialization: reconstructing the last half year from AD replication metadata ({scope})", "domain",
                pending.Count > 0 && only == null ? $"Changes made on {string.Join(", ", pending)} follow once that DC can be read." : "");
            var (added, skipped) = new Reconstructor(_store, _cfg, include, (text, p) => { _phaseDetail = text; _phaseProgress = p; }, _cts.Token).Run();
            AppendSystem(Cat.Service, $"AD history imported: {added:N0} historic changes reconstructed ({scope})", "domain",
                $"{skipped:N0} were already known from Security logs and were not added twice.");
            foreach (var d in _dcs.Values.Where(d => BackfillDone(d.Name) && (only == null || only.Contains(d.Name))))
                _store.SetMeta("recon_done:" + d.Name, DateTime.UtcNow.ToString("o"));
            if (only == null) _store.SetMeta("init_done", DateTime.UtcNow.ToString("o"));
        }
        catch (OperationCanceledException) { return; }
        catch (Exception ex)
        {
            Log.Error("Reconstruction from AD metadata failed (will retry at next service start)", ex);
            AppendSystem(Cat.Service, "Initialization: AD history reconstruction failed", "domain", ex.Message);
            if (only == null) _store.SetMeta("init_done", "failed " + DateTime.UtcNow.ToString("o"));
            else foreach (var d in only) _store.SetMeta("recon_done:" + d, "failed " + DateTime.UtcNow.ToString("o"));
        }
        _phase = "Live";
        _phaseDetail = null;
        _phaseProgress = null;
    }
    void Discover()
    {
        if (DateTime.UtcNow - _lastDiscovery < TimeSpan.FromMinutes(10)) return;
        _lastDiscovery = DateTime.UtcNow;
        _discoveryWarnings.Clear();
        var names = new List<string>(_cfg.DomainControllers);
        if (names.Count == 0)
        {
            try
            {
                using var domain = Domain.GetComputerDomain();
                foreach (DomainController dc in domain.DomainControllers) names.Add(dc.Name);
            }
            catch (Exception ex)
            {
                _discoveryWarnings.Add("DC discovery failed, collecting local log only: " + ex.Message);
            }
        }
        var local = Environment.MachineName.ToUpperInvariant();
        if (!names.Any(n => n.Split('.')[0].Equals(local, StringComparison.OrdinalIgnoreCase))) names.Add(local);

        foreach (var fqdn in names)
        {
            var shortName = fqdn.Split('.')[0].ToUpperInvariant();
            if (_dcs.ContainsKey(shortName)) continue;
            var src = new DcSource(fqdn, shortName == local);
            src.Status.LastRecordId = _store.GetBookmark(src.Name);
            _dcs[shortName] = src;
            Log.Info($"Collecting Security log of {fqdn}{(src.IsLocal ? " (local)" : " (remote)")}");
        }
    }

    /// <returns>true if any DC had more events than one batch (read again soon).</returns>
    bool Cycle()
    {
        Discover();
        var all = new List<RawEvent>();
        var bookmarks = new Dictionary<string, long>();
        bool more = false;
        int batch = _phase == "Backfill" ? BackfillBatch : LiveBatch;

        foreach (var dc in _dcs.Values)
        {
            if (DateTime.UtcNow < dc.NextRetryUtc) continue; // unreachable: retried with back-off
            try
            {
                long bm = _store.GetBookmark(dc.Name);
                var (oldest, newest, count) = dc.LogRange();
                if (bm > 0 && count > 0 && newest < bm)
                {
                    AppendSystem(Cat.Tamper, "Security log record numbers were reset", $"Security log on {dc.Name}",
                        $"Bookmark {bm}, newest record now {newest}. The log was recreated or replaced.");
                    bm = 0;
                    bookmarks[dc.Name] = 0;
                }
                else if (bm > 0 && count > 0 && oldest > bm + 1)
                {
                    AppendSystem(Cat.Tamper, $"{oldest - bm - 1:N0} Security log records lost before collection", $"Security log on {dc.Name}",
                        $"Records {bm + 1}–{oldest - 1} were overwritten while {dc.Name} could not be read. Increase the Security log size.");
                    bm = oldest - 1;
                    bookmarks[dc.Name] = bm;
                }

                var evs = dc.ReadSince(bm, batch);
                if (evs.Count >= batch) more = true;
                evs = DeferIncompleteModification(evs);
                if (evs.Count > 0)
                {
                    all.AddRange(evs);
                    bookmarks[dc.Name] = evs[^1].RecordId;
                    dc.Status.LastRecordId = evs[^1].RecordId;
                    dc.Status.LastEventUtc = evs[^1].TimeUtc;
                }
                if (_phase == "Backfill" && count > 0)
                {
                    long pos = Math.Max(bookmarks.TryGetValue(dc.Name, out var b) ? b : bm, oldest);
                    _backfill[dc.Name] = evs.Count >= batch ? Math.Clamp((double)(pos - oldest) / Math.Max(1, newest - oldest), 0, 0.99) : 1;
                }
                if (evs.Count < batch && !BackfillDone(dc.Name))
                {
                    _store.SetMeta("bf_done:" + dc.Name, DateTime.UtcNow.ToString("o"));
                    if (_phase == "Backfill") _backfill[dc.Name] = 1;
                }
                if (dc.Failures > 0) Log.Info($"{dc.Fqdn} is reachable again");
                dc.Failures = 0;
                dc.Status.Ok = true;
                dc.Status.LastError = null;
                dc.Status.LastPollUtc = DateTime.UtcNow;
            }
            catch (Exception ex)
            {
                if (dc.Status.Ok || dc.Status.LastError == null) Log.Error($"Cannot read Security log of {dc.Fqdn}", ex);
                dc.Status.Ok = false;
                dc.Status.LastError = ex is UnauthorizedAccessException
                    ? $"Access denied reading the Security log of {dc.Name}. Add 'Domain Controllers' to 'Event Log Readers', then run 'klist -li 0x3e7 purge' on {Environment.MachineName} and restart the AD Audit service."
                    : ex.Message;
                dc.Failures++;
                dc.NextRetryUtc = DateTime.UtcNow.AddMinutes(Math.Min(10, dc.Failures)); // 1, 2, … 10 min
            }
        }

        if (_phase == "Backfill")
        {
            _phaseProgress = _backfill.Count == 0 ? 0 : _backfill.Values.Average();
            _phaseDetail = "Reading historic Security log events: " +
                           string.Join(", ", _backfill.Select(kv => $"{kv.Key} {kv.Value:P0}"));
        }

        if (all.Count == 0)
        {
            if (bookmarks.Count > 0) _store.Append(Array.Empty<AuditEntry>(), bookmarks);
            return false;
        }

        all.Sort((a, b) => a.TimeUtc != b.TimeUtc ? a.TimeUtc.CompareTo(b.TimeUtc)
                         : string.CompareOrdinal(a.Dc, b.Dc) != 0 ? string.CompareOrdinal(a.Dc, b.Dc)
                         : a.RecordId.CompareTo(b.RecordId));
        var entries = _builder.Build(all);
        var inserted = _store.Append(entries, bookmarks);
        if (inserted.Count > 0) Log.Info($"Stored {inserted.Count} new entries");
        _guard.OnNewEntries(inserted);
        return more;
    }

    /// <summary>
    /// One LDAP modify produces several 5136 events (value deleted + value added) sharing a correlation id.
    /// If the newest events belong to a modification that may still be in progress, keep them for the next cycle.
    /// </summary>
    static List<RawEvent> DeferIncompleteModification(List<RawEvent> evs)
    {
        if (evs.Count == 0) return evs;
        var last = evs[^1];
        if (last.EventId != 5136 || DateTime.UtcNow - last.TimeUtc > TimeSpan.FromSeconds(15)) return evs;
        var corr = last.D("OpCorrelationID");
        int i = evs.Count;
        while (i > 0 && evs[i - 1].EventId == 5136 && evs[i - 1].D("OpCorrelationID") == corr) i--;
        return evs.GetRange(0, i);
    }

    void Maintenance()
    {
        if (DateTime.UtcNow - _lastMaintenance < TimeSpan.FromHours(1)) return;
        _lastMaintenance = DateTime.UtcNow;
        int purged = _store.Purge(_cfg.EffectiveRetentionDays);
        if (purged > 0)
            AppendSystem(Cat.Service, $"Retention: {purged:N0} entries older than {_cfg.EffectiveRetentionDays} days removed", "audit database");
        var (id, hash) = _store.Head();
        // Anchor the chain head in the Windows event log (forward it to a SIEM for off-box proof).
        Log.WriteEventLog($"ADAudit chain head: entry #{id}, hash {hash}", EventLogEntryType.Information, 1100);
        if (DateTime.UtcNow - _lastFullVerify > TimeSpan.FromHours(6)) Verify(force: true);
        GC.Collect(2, GCCollectionMode.Optimized, false, true); // hand unused memory back after big batches
    }

    /// <summary>Incremental chain check (new entries only); full re-check when forced and at most every 6 h in background.</summary>
    VerifyResult Verify(bool force)
    {
        lock (_verifyGate)
        {
            if (!force && _lastVerify != null && DateTime.UtcNow - _lastVerify.VerifiedUtc < TimeSpan.FromSeconds(30)) return _lastVerify;
            if (force && _lastVerify != null && DateTime.UtcNow - _lastFullVerify < TimeSpan.FromMinutes(1)) return _lastVerify;
            bool full = force || _lastVerify is not { Ok: true };
            var r = _store.Verify(full ? 0 : _verifiedId, full ? null : _verifiedHash, out var id, out var hash);
            if (full) { _verifiedCount = 0; _lastFullVerify = DateTime.UtcNow; }
            if (r.Ok)
            {
                _verifiedId = id;
                _verifiedHash = hash;
                _verifiedCount += r.Checked;
                r.Checked = _verifiedCount;
                r.Message = $"All {_verifiedCount:N0} entries intact (last full check {_lastFullVerify.ToLocalTime():yyyy-MM-dd HH:mm}).";
            }
            else Log.WriteEventLog("ADAudit integrity check FAILED: " + r.Message, EventLogEntryType.Error, 1101);
            _lastVerify = r;
            return r;
        }
    }

    // ───────────────────────── request handling (named pipe) ─────────────────────────

    internal PipeResponse Handle(PipeRequest req, string caller, string computer = "")
    {
        switch (req.Op)
        {
            case "settings-get":
                return new PipeResponse { Settings = CurrentSettings() };
            case "settings-set":
                return new PipeResponse { Settings = SaveSettings(req.Settings ?? throw new ArgumentException("no settings"), caller, computer) };
            case "settings-testmail":
                return new PipeResponse { Message = TestMail(req.Settings ?? throw new ArgumentException("no settings"), caller) };
            case "guard-ack":
                return new PipeResponse { Message = Acknowledge(req.Id ?? 0, req.Text ?? "", caller, computer) };
            case "acks-list":
                return new PipeResponse { Acks = _store.Acks(activeOnly: true) };
            case "ack-revoke":
                return new PipeResponse { Message = RevokeAck(req.Id ?? 0, caller, computer) };
            case "query":
                var qr = _store.Query(req.Query ?? new QueryRequest());
                foreach (var item in qr.Items) _resolver.Annotate(item);
                return new PipeResponse { Query = qr };
            case "get":
                var one = req.Id.HasValue ? _store.Get(req.Id.Value) : null;
                if (one != null) _resolver.Annotate(one);
                return new PipeResponse { Entry = one };
            case "verify":
                return new PipeResponse { Verify = Verify(req.Force) };
            case "dashboard":
                return new PipeResponse { Dashboard = _store.Dashboard(req.Dashboard ?? new DashboardRequest { FromUtc = DateTime.UtcNow.AddDays(-30), ToUtc = DateTime.UtcNow }) };
            case "guard":
                var items = _store.GuardItems(pendingOnly: false);
                foreach (var gi in items)
                    gi.Ackable = gi.Status is GuardStatus.Unacknowledged or GuardStatus.Pending or GuardStatus.AlertOnly &&
                                 _guard.RuleFor(gi.GroupGuid, gi.GroupName) is { RequireAck: true };
                return new PipeResponse { Guard = items };
            case "status":
                var (count, oldest, newest) = _store.Stats();
                using (var p = Process.GetCurrentProcess())
                {
                    var st = new StatusInfo
                    {
                        Host = Environment.MachineName,
                        Version = Version,
                        ServiceStartedUtc = _started,
                        TotalEntries = count,
                        OldestUtc = oldest,
                        NewestUtc = newest,
                        RetentionDays = _cfg.EffectiveRetentionDays,
                        Phase = _phase,
                        PhaseDetail = _phaseDetail,
                        PhaseProgress = _phase == "Live" ? null : _phaseProgress,
                        ServiceMemoryMb = Math.Round(p.PrivateMemorySize64 / 1048576.0, 1),
                        ServiceCpuSeconds = Math.Round(p.TotalProcessorTime.TotalSeconds, 1),
                        Caller = caller,
                        Dcs = _dcs.Values.Select(d => d.Status).OrderBy(d => d.Name).ToList(),
                    };
                    st.Warnings.AddRange(_discoveryWarnings);
                    foreach (var d in _dcs.Values.Where(d => !d.Status.Ok && d.Status.LastError != null))
                        st.Warnings.Add($"{d.Name}: {d.Status.LastError}");
                    st.Warnings.AddRange(_guard.Warnings);
                    return new PipeResponse { Status = st };
                }
            default:
                return new PipeResponse { Ok = false, Error = "Unknown operation " + req.Op };
        }
    }

    AlertSettings CurrentSettings() => new()
    {
        Rules = _cfg.GuardedGroups.Select(g => new GuardRule
        {
            Name = g.Name, DomainRid = g.DomainRid, Alert = g.Alert, AutoRemove = g.AutoRemove,
            RemoveAfterMinutes = g.MaxMembershipMinutes, RequireAck = g.RequireAck,
        }).ToList(),
        PopupAlerts = _cfg.PopupAlerts,
        SmtpHost = _cfg.Smtp?.Host ?? "",
        SmtpPort = _cfg.Smtp?.Port ?? 25,
        SmtpSsl = _cfg.Smtp?.UseSsl ?? false,
        SmtpFrom = _cfg.Smtp?.From ?? "",
        SmtpTo = string.Join("; ", _cfg.Smtp?.To ?? new List<string>()),
        SmtpUser = _cfg.Smtp?.User ?? "",
        SmtpHasPassword = (_cfg.Smtp?.PasswordProtected.Length ?? 0) > 0,
    };

    static string Describe(AlertSettings s) =>
        string.Join("\n", s.Rules.Select(r => $"{r.Name}{(r.DomainRid is int rid ? $" (RID {rid})" : "")}: " +
            $"{(r.Alert ? "alert" : "no alert")}, {(r.AutoRemove ? $"remove after {r.RemoveAfterMinutes} min" : "no removal")}" +
            $"{(r.RequireAck ? ", acknowledgment required" : "")}")) +
        $"\nPop-ups: {(s.PopupAlerts ? "on" : "off")}\nE-mail: {(s.SmtpHost.Length > 0 && s.SmtpTo.Length > 0 ? $"{s.SmtpHost}:{s.SmtpPort}{(s.SmtpSsl ? " TLS" : "")} → {s.SmtpTo}" : "off")}" +
        (s.SmtpUser.Length > 0 ? $"\nSMTP login: {s.SmtpUser} (password {(s.SmtpHasPassword ? "stored" : "not set")})" : "");

    /// <summary>SMTP settings from the dialog; the stored password is kept unless a new one was typed.</summary>
    SmtpSettings? BuildSmtp(AlertSettings s)
    {
        if (s.SmtpHost.Trim().Length == 0) return null;
        var smtp = new SmtpSettings
        {
            Host = s.SmtpHost.Trim(), Port = s.SmtpPort, UseSsl = s.SmtpSsl, From = s.SmtpFrom.Trim(), User = s.SmtpUser.Trim(),
            To = s.SmtpTo.Split(new[] { ',', ';', ' ' }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).ToList(),
            PasswordProtected = s.SmtpClearPassword ? "" : _cfg.Smtp?.PasswordProtected ?? "",
        };
        if (!string.IsNullOrEmpty(s.SmtpPasswordNew)) smtp.SetPassword(s.SmtpPasswordNew);
        return smtp;
    }

    string TestMail(AlertSettings s, string caller)
    {
        var smtp = BuildSmtp(s) ?? throw new ArgumentException("Enter an SMTP server first.");
        if (smtp.To.Count == 0) throw new ArgumentException("Enter at least one recipient.");
        GroupGuard.SendMail(smtp, "Test mail", $"This is a test mail from AD Audit Trail, requested by {caller}.\nAlerts for watched groups will be delivered like this.");
        return $"Test mail sent to {string.Join(", ", smtp.To)}.";
    }

    string Acknowledge(long id, string reason, string caller, string computer)
    {
        reason = reason.Trim();
        if (reason.Length < 3) throw new ArgumentException("Please enter a reason.");
        var g = _store.GetGuard(id) ?? throw new ArgumentException("Alert not found.");
        if (_guard.RuleFor(g.GroupGuid, g.GroupName) is not { RequireAck: true })
            throw new InvalidOperationException($"Acknowledging is not enabled for {g.GroupName} (Settings).");
        if (g.Status is GuardStatus.Acknowledged) return "Already acknowledged.";
        var who = Dn.FriendlyName(g.MemberDn);
        bool cancelsRemoval = g.Status == GuardStatus.Pending;
        _store.UpdateGuard(id, GuardStatus.Acknowledged, $"Acknowledged by {caller}: {reason}", false);
        _store.AddAck(new AckInfo
        {
            GroupGuid = g.GroupGuid, GroupName = g.GroupName, MemberDn = g.MemberDn, MemberSid = g.MemberSid,
            Reason = reason, By = caller, FromHost = computer,
        });
        AppendSystem(Cat.Guard, $"Membership acknowledged: {who} in {g.GroupName}", g.GroupDn,
            $"Reason: {reason}\nAcknowledged by {caller} from {computer}\nTrigger entry #{g.AuditId}" +
            (cancelsRemoval ? "\nThe scheduled automatic removal was cancelled." : ""), "", g.MemberDn, actor: caller, sourceHost: computer);
        return $"{who} is now an acknowledged member of {g.GroupName}.";
    }

    string RevokeAck(long id, string caller, string computer)
    {
        var a = _store.GetAck(id) ?? throw new ArgumentException("Acknowledgment not found.");
        if (a.RevokedUtc != null) return "Already revoked.";
        _store.RevokeAck(id, caller);
        AppendSystem(Cat.Guard, $"Acknowledgment revoked: {a.MemberName} in {a.GroupName}", a.GroupName,
            $"Originally acknowledged by {a.By} on {a.AckUtc.ToLocalTime():yyyy-MM-dd HH:mm}: {a.Reason}\nRevoked by {caller} from {computer}. " +
            "The next time this member is added, an alert is raised again.", a.MemberDn, "", actor: caller, sourceHost: computer);
        return "Acknowledgment revoked.";
    }

    /// <summary>Applies alert settings from a viewer; the change itself becomes part of the audit trail.</summary>
    AlertSettings SaveSettings(AlertSettings s, string caller, string computer)
    {
        foreach (var r in s.Rules)
        {
            r.Name = r.Name.Trim();
            if (r.Name.Length == 0 && r.DomainRid == null) throw new ArgumentException("Every rule needs a group name.");
            if (r.RemoveAfterMinutes is < 1 or > 43200) throw new ArgumentException($"{r.Name}: removal time must be between 1 minute and 30 days.");
        }
        var before = Describe(CurrentSettings());
        _cfg.GuardedGroups = s.Rules.Select(r => new GuardedGroup
        {
            Name = r.Name, DomainRid = r.DomainRid, Alert = r.Alert, AutoRemove = r.AutoRemove,
            MaxMembershipMinutes = r.RemoveAfterMinutes, RequireAck = r.RequireAck,
        }).ToList();
        _cfg.PopupAlerts = s.PopupAlerts;
        _cfg.Smtp = BuildSmtp(s);
        _cfg.Save();
        _guard.Reload();
        var after = Describe(CurrentSettings());
        if (!string.IsNullOrEmpty(s.SmtpPasswordNew)) after += "\nSMTP password changed";
        else if (s.SmtpClearPassword) after += "\nSMTP password removed";
        if (before != after)
            AppendSystem(Cat.Policy, "Alert settings changed", "ADAudit settings", $"Changed by {caller} from {computer}", before, after,
                actor: caller, sourceHost: computer);
        return CurrentSettings();
    }

    // viewer sessions are part of the trail: who looked, from which machine
    readonly Dictionary<string, DateTime> _viewerSeen = new();

    internal void ViewerConnected(string user, string computer)
    {
        var key = user + "|" + computer;
        lock (_viewerSeen)
        {
            if (_viewerSeen.TryGetValue(key, out var t) && DateTime.UtcNow - t < TimeSpan.FromMinutes(30)) return;
            _viewerSeen[key] = DateTime.UtcNow;
        }
        try
        {
            AppendSystem(Cat.Service, "Audit trail viewed", "ADAudit viewer", $"Viewer session opened by {user} from {computer}",
                actor: user, sourceHost: computer);
        }
        catch (Exception ex) { Log.Warn("Cannot record viewer session: " + ex.Message); }
    }
}

/// <summary>
/// Named pipe endpoint. ACL: SYSTEM, Administrators of the DC (= Domain/Enterprise Admins + built-in admins)
/// and optional viewer groups. Reachable remotely as \\DC\pipe\ADAudit.v1 (SMB, Kerberos) unless disabled.
/// The protocol has read operations only.
/// </summary>
sealed class PipeServer
{
    readonly Engine _engine;
    readonly Config _cfg;
    readonly CancellationTokenSource _cts = new();

    public PipeServer(Engine engine, Config cfg)
    {
        _engine = engine;
        _cfg = cfg;
    }

    public void Start()
    {
        for (int i = 0; i < 4; i++) Task.Run(AcceptLoop);
    }

    public void Stop() => _cts.Cancel();

    PipeSecurity Security()
    {
        var ps = new PipeSecurity();
        if (!_cfg.AllowRemoteViewers)
            ps.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.NetworkSid, null), PipeAccessRights.FullControl, AccessControlType.Deny));
        ps.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null), PipeAccessRights.FullControl, AccessControlType.Allow));
        ps.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null), PipeAccessRights.ReadWrite, AccessControlType.Allow));
        foreach (var g in _cfg.ViewerGroups)
        {
            try
            {
                var sid = g.StartsWith("S-1-", StringComparison.OrdinalIgnoreCase)
                    ? new SecurityIdentifier(g)
                    : (SecurityIdentifier)new NTAccount(g).Translate(typeof(SecurityIdentifier));
                ps.AddAccessRule(new PipeAccessRule(sid, PipeAccessRights.ReadWrite, AccessControlType.Allow));
            }
            catch (Exception ex) { Log.Warn($"Viewer group '{g}' ignored: {ex.Message}"); }
        }
        return ps;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern bool GetNamedPipeClientComputerName(IntPtr pipe, StringBuilder name, int size);

    static string ClientComputer(NamedPipeServerStream s)
    {
        var sb = new StringBuilder(256);
        bool remote = GetNamedPipeClientComputerName(s.SafePipeHandle.DangerousGetHandle(), sb, sb.Capacity * 2);
        return remote && sb.Length > 0 ? sb.ToString() : $"{Environment.MachineName} (local)";
    }

    async Task AcceptLoop()
    {
        while (!_cts.IsCancellationRequested)
        {
            try
            {
                using var server = NamedPipeServerStreamAcl.Create(Proto.PipeName, PipeDirection.InOut,
                    NamedPipeServerStream.MaxAllowedServerInstances, PipeTransmissionMode.Byte, PipeOptions.Asynchronous, 0, 0, Security());
                await server.WaitForConnectionAsync(_cts.Token);

                string user;
                try { user = server.GetImpersonationUserName(); } catch { user = "(unknown account)"; }
                var computer = ClientComputer(server);
                _engine.ViewerConnected(user, computer);

                using var reader = new StreamReader(server, new UTF8Encoding(false), false, 65536, leaveOpen: true);
                using var writer = new StreamWriter(server, new UTF8Encoding(false), 65536, leaveOpen: true);
                while (server.IsConnected && !_cts.IsCancellationRequested)
                {
                    var line = await reader.ReadLineAsync(_cts.Token);
                    if (line == null) break;
                    PipeResponse resp;
                    try
                    {
                        var req = JsonSerializer.Deserialize<PipeRequest>(line, Proto.Json) ?? new PipeRequest();
                        resp = await Task.Run(() => _engine.Handle(req, user, computer));
                    }
                    catch (Exception ex)
                    {
                        resp = new PipeResponse { Ok = false, Error = ex.Message };
                    }
                    await writer.WriteLineAsync(JsonSerializer.Serialize(resp, Proto.Json));
                    await writer.FlushAsync();
                }
            }
            catch (OperationCanceledException) { }
            catch (Exception ex)
            {
                Log.Warn("Pipe: " + ex.Message);
                await Task.Delay(500);
            }
        }
    }
}
