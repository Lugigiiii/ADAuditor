using System.Security.Cryptography;
using ADAudit.Shared;
using Microsoft.Data.Sqlite;

namespace ADAudit.Service;

/// <summary>ADAudit.exe --selftest : verifies storage guarantees on a throw-away database.</summary>
static class SelfTest
{
    public static int Run()
    {
        if (!Console.IsOutputRedirected) Native.AllocConsole();
        var path = Path.Combine(Path.GetTempPath(), $"adaudit-selftest-{Guid.NewGuid():N}.db");
        int failed = 0;
        var key = RandomNumberGenerator.GetBytes(32);
        void Check(string name, bool ok) { Console.WriteLine($"  [{(ok ? "PASS" : "FAIL")}] {name}"); if (!ok) failed++; }

        try
        {
            var g =Guid.NewGuid().ToString();
            var t = DateTime.UtcNow.AddMinutes(-30);
            AuditEntry Mod(string sk, int min, string old, string nw, string attr = "member") => new()
            {
                SourceKey = sk, TimeUtc = t.AddMinutes(min), Dc = "DC01", EventId = 5136, Category = Cat.Modify, Action = "test",
                Actor = "CORP\\tester", TargetDn = "CN=Temp_Admins,DC=corp,DC=local", TargetGuid = g, Attribute = attr, OldValue = old, NewValue = nw,
            };

            using (var store = new AuditStore(path, key))
            {
                var add = store.Append(new[] { Mod("DC01:1:1", 0, "", "CN=Tom,DC=corp,DC=local") }, new Dictionary<string, long> { ["DC01"] = 1 });
                var dup = store.Append(new[] { Mod("DC01:1:1", 0, "", "CN=Tom,DC=corp,DC=local") }, null);
                Check("duplicate event is stored only once", add.Count == 1 && dup.Count == 0);
                Check("bookmark persisted atomically", store.GetBookmark("DC01") == 1);

                // the removal arrives from the other DC
                var rem = store.Append(new[] { Mod("DC02:7:2", 10, "CN=Tom,DC=corp,DC=local", "") }, null);
                var a = store.Get(add[0].Id)!;
                var r = store.Get(rem[0].Id)!;
                Check("add + remove are linked as revert", a.RevertedById == r.Id && r.RevertsId == a.Id);

                // single-valued A→B, B→A; late-arriving older event links correctly
                var ab = store.Append(new[] { Mod("DC01:3:3", 5, "Sales", "Finance", "department") }, null)[0];
                var ba = store.Append(new[] { Mod("DC02:4:4", 3 + 20, "Finance", "Sales", "department") }, null)[0];
                Check("A→B then B→A linked", store.Get(ab.Id)!.RevertedById == ba.Id);

                var q = store.Query(new QueryRequest { Text = "Tom", OnlyReverted = true });
                Check("full-text search + reverted filter", q.TotalMatches == 2);
                Check("substring search (trigram)", store.Query(new QueryRequest { Text = "inanc" }).TotalMatches == 2);
                Check("exclusion search", store.Query(new QueryRequest { Text = "-Tom" }).TotalMatches == 2);
                Check("integrity chain verifies", store.Verify(0, null, out var vid, out var vh).Ok);
                Check("incremental verify continues from last checked entry", store.Verify(vid, vh, out _, out _) is { Ok: true, Checked: 0 });
                Check("reconstructed duplicate is recognised", store.HasSimilar(g, Cat.Modify, "member", t.AddSeconds(3), "CN=Tom,DC=corp,DC=local", null));
                Check("different change is not treated as duplicate", !store.HasSimilar(g, Cat.Modify, "member", t.AddMinutes(3), "CN=Tom,DC=corp,DC=local", null));
                var dash = store.Dashboard(new DashboardRequest { FromUtc = t.AddHours(-1), ToUtc = DateTime.UtcNow.AddHours(1), Buckets = 10 });
                Check("dashboard totals + grouping", dash.Total == 4 && dash.Membership == 2 && dash.Reverted == 2 && dash.Groups.Sum(x => x.Count) == 4 && dash.Series.Sum(s => s.Changes) == 4);

                // no-op (ADUC re-writes primaryGroupID 513 → 513): never linked, hidden from queries
                var a1 = store.Append(new[] { Mod("DC01:20:20", 1, "1105", "513", "primaryGroupID") }, null)[0];
                var noop = store.Append(new[] { Mod("DC01:21:21", 2, "513", "513", "primaryGroupID") }, null)[0];
                Check("no-op change is not linked as a revert", store.Get(noop.Id)!.RevertsId == null && store.Get(a1.Id)!.RevertedById == null);
                Check("no-op change hidden from the log", store.Query(new QueryRequest { Text = "primaryGroupID" }).TotalMatches == 1);
                Check("no-op change visible with 'System noise'", store.Query(new QueryRequest { Text = "primaryGroupID", IncludeNoise = true }).TotalMatches == 2);
                var spn = new AuditEntry { Category = Cat.Modify, EventId = 5136, Actor = "CORP\\PC042$ (computer)", TargetDn = "CN=PC042,OU=Clients,DC=corp,DC=local",
                    TargetClass = "computer", Attribute = "servicePrincipalName", NewValue = "TERMSRV/PC042" };
                Check("computer updating its own SPN is noise", Noise.IsNoise(spn));
                Check("admin changing a computer's SPN is kept", !Noise.IsNoise(new AuditEntry { Category = Cat.Modify, EventId = 5136, Actor = "CORP\\admin",
                    TargetDn = spn.TargetDn, TargetClass = "computer", Attribute = "servicePrincipalName", NewValue = "HTTP/x" }));
                // re-adding someone who was removed long ago is a new change, not a revert
                var oldRemove = store.Append(new[] { Mod("DC01:40:40", -60 * 24 * 30, "CN=Old,DC=corp,DC=local", "") }, null)[0];
                var reAdd = store.Append(new[] { Mod("DC01:41:41", 3, "", "CN=Old,DC=corp,DC=local") }, null)[0];
                Check("no revert link across more than 7 days", store.Get(reAdd.Id)!.RevertsId == null && store.Get(oldRemove.Id)!.RevertedById == null);
                var quickRemove = store.Append(new[] { Mod("DC01:42:42", 4, "CN=Old,DC=corp,DC=local", "") }, null)[0];
                Check("removal minutes later is linked as revert", store.Get(quickRemove.Id)!.RevertsId == reAdd.Id);

                // temporary-membership group (automatic removal): re-adding after a removal is NOT an undo; the removal is
                store.TemporaryGroups = () => new[] { g };
                var tRem = store.Append(new[] { Mod("DC01:50:50", 5, "CN=Maint,DC=corp,DC=local", "") }, null)[0];
                var tAdd = store.Append(new[] { Mod("DC01:51:51", 6, "", "CN=Maint,DC=corp,DC=local") }, null)[0];
                Check("temporary group: re-addition is not shown as undoing the earlier removal", store.Get(tAdd.Id)!.RevertsId == null);
                var tRem2 = store.Append(new[] { Mod("DC01:52:52", 66, "CN=Maint,DC=corp,DC=local", "") }, null)[0];
                Check("temporary group: the removal one hour later undoes the addition", store.Get(tRem2.Id)!.RevertsId == tAdd.Id);
                store.TemporaryGroups = () => Array.Empty<string>();

                // acknowledged memberships
                var ackId = store.AddAck(new AckInfo { GroupGuid = "g-da", GroupName = "Domain Admins", MemberDn = "CN=New Admin,OU=IT,DC=corp,DC=local",
                    MemberSid = "S-1-5-21-1-2-3-1500", Reason = "joined IT admin team", By = "CORP\\boss", FromHost = "PC1" });
                Check("acknowledgment found by SID (even after rename)", store.FindAck("g-da", "S-1-5-21-1-2-3-1500", "CN=Renamed,OU=IT,DC=corp,DC=local") != null);
                Check("acknowledgment is per group", store.FindAck("g-other", "S-1-5-21-1-2-3-1500", "x") == null);
                store.RevokeAck(ackId, "CORP\\boss");
                Check("revoked acknowledgment no longer applies", store.FindAck("g-da", "S-1-5-21-1-2-3-1500", "x") == null && store.Acks(true).Count == 0);
                Check("delegation self-write is kept", !Noise.IsNoise(new AuditEntry { Category = Cat.Modify, EventId = 5136, Actor = spn.Actor,
                    TargetDn = spn.TargetDn, TargetClass = "computer", Attribute = "msDS-AllowedToActOnBehalfOfOtherIdentity", NewValue = "x" }));            }

            using var raw = new SqliteConnection($"Data Source={path};Pooling=False");
            raw.Open();
            bool Throws(string sql)
            {
                try { using var c = raw.CreateCommand(); c.CommandText = sql; c.ExecuteNonQuery(); return false; }
                catch (SqliteException) { return true; }
            }
            Check("UPDATE on audit trail is rejected", Throws("UPDATE audit SET actor='someone else'"));
            Check("DELETE of recent entries is rejected", Throws("DELETE FROM audit"));
            Check("UPDATE on revert links is rejected", Throws("UPDATE links SET kind='x'"));

            // simulate an attacker who drops the trigger and edits a row directly
            using (var c = raw.CreateCommand())
            {
                c.CommandText = "DROP TRIGGER audit_no_update; UPDATE audit SET actor='CORP\\innocent' WHERE id=1;";
                c.ExecuteNonQuery();
            }
            raw.Close();
            using (var store = new AuditStore(path, key))
            {
                var v = store.Verify(0, null, out _, out _);
                Check($"direct database edit is detected by Verify() → \"{v.Message}\"", !v.Ok && v.FirstBadId == 1);
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine("  [FAIL] unexpected: " + ex);
            failed++;
        }
        finally
        {
            SqliteConnection.ClearAllPools();
            foreach (var f in Directory.GetFiles(Path.GetTempPath(), Path.GetFileName(path) + "*")) try { File.Delete(f); } catch { }
        }

        Console.WriteLine(failed == 0 ? "\nAll self-tests passed." : $"\n{failed} self-test(s) FAILED.");
        if (!Console.IsInputRedirected && Environment.GetCommandLineArgs().All(a => a != "--quiet")) { Console.WriteLine("Press Enter."); Console.ReadLine(); }
        return failed == 0 ? 0 : 1;
    }
}
