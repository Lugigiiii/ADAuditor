using System.Diagnostics;
using System.DirectoryServices;
using System.DirectoryServices.ActiveDirectory;
using System.Security.AccessControl;
using System.Security.Principal;
using System.ServiceProcess;
using System.Text;
using ADAudit.Service;
using ADAudit.Shared;

namespace ADAudit.Install;

/// <summary>
/// ADAudit.exe --install : installs/upgrades the service (LocalSystem) and configures auditing on all DCs.
/// ADAudit.exe --uninstall : removes the service (the audit database is kept).
/// </summary>
static class Installer
{
    static readonly string InstallDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "ADAudit");
    static readonly string ExePath = Path.Combine(InstallDir, "ADAudit.exe");
    static readonly string Shortcut = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonPrograms), "AD Audit Trail.lnk");

    // Service DACL: SYSTEM full; Administrators may query/start/read and change the DACL (needed for uninstall),
    // but cannot stop, pause, reconfigure or delete without first changing the DACL (which is itself logged).
    const string HardenedSddl = "D:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)(A;;CCLCSWRPLOCRRCWD;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)";
    const string DefaultSddl = "D:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)";

    static readonly List<string> Problems = new();

    public static int Install(bool quiet)
    {
        Native.AllocConsole();
        Console.OutputEncoding = Encoding.UTF8;
        Console.WriteLine("AD Audit Trail – installation\n");

        bool exists = ServiceController.GetServices().Any(s => s.ServiceName == Proto.ServiceName);

        Step("Stop existing service (upgrade)", () =>
        {
            if (!exists) { Console.Write("not installed yet "); return; }
            Run("sc.exe", $"sdset {Proto.ServiceName} \"{DefaultSddl}\"");
            using var sc = new ServiceController(Proto.ServiceName);
            if (sc.Status != ServiceControllerStatus.Stopped)
            {
                sc.Stop();
                sc.WaitForStatus(ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(60));
            }
        });

        Step($"Copy program to {InstallDir}", () =>
        {
            Directory.CreateDirectory(InstallDir);
            var self = Environment.ProcessPath!;
            if (!string.Equals(Path.GetFullPath(self), Path.GetFullPath(ExePath), StringComparison.OrdinalIgnoreCase))
                ReplaceExe(self);
        });

        Step("Create data folder (SYSTEM: full, Administrators: read-only)", () =>
        {
            Config.WriteDefault();
            Config.SecureDataDir();
        });

        Step("Register event log source 'ADAudit'", () =>
        {
            if (!EventLog.SourceExists(Proto.EventSource)) EventLog.CreateEventSource(Proto.EventSource, "Application");
        });

        Step("Create Windows service 'ADAudit' (runs as LocalSystem)", () =>
        {
            var bin = $"\\\"{ExePath}\\\" --service";
            if (!exists)
                Run("sc.exe", $"create {Proto.ServiceName} binPath= \"{bin}\" start= delayed-auto obj= LocalSystem DisplayName= \"AD Audit Trail\"", true);
            else
                Run("sc.exe", $"config {Proto.ServiceName} binPath= \"{bin}\" start= delayed-auto obj= LocalSystem", true);
            Run("sc.exe", $"description {Proto.ServiceName} \"Immutable Active Directory audit trail and group guard\"");
            Run("sc.exe", $"failure {Proto.ServiceName} reset= 86400 actions= restart/5000/restart/5000/restart/30000", true);
            Run("sc.exe", $"failureflag {Proto.ServiceName} 1");
        });

        string domainDn = "", domainSid = "";
        List<string> dcs = new();
        Step("Discover domain and domain controllers", () =>
        {
            using var rootDse = new DirectoryEntry("LDAP://RootDSE");
            domainDn = (string)rootDse.Properties["defaultNamingContext"].Value!;
            using var dom = new DirectoryEntry("LDAP://" + domainDn);
            domainSid = new SecurityIdentifier((byte[])dom.Properties["objectSid"].Value!, 0).Value;
            using var d = Domain.GetComputerDomain();
            foreach (DomainController dc in d.DomainControllers) dcs.Add(dc.Name);
            Console.Write($"{domainDn}; DCs: {string.Join(", ", dcs)} ");
        });

        if (domainDn.Length > 0)
        {
            Step("Audit SACL on domain partition (Everyone: write/create/delete/move, success)", () => AddSacl(domainDn, ActiveDirectorySecurityInheritance.All));
            Step("Audit SACL on AdminSDHolder (protected admin accounts/groups)", () => AddSacl($"CN=AdminSDHolder,CN=System,{domainDn}", ActiveDirectorySecurityInheritance.None));
            Step("Audit SACL on Configuration partition", () =>
            {
                using var rootDse = new DirectoryEntry("LDAP://RootDSE");
                AddSacl((string)rootDse.Properties["configurationNamingContext"].Value!, ActiveDirectorySecurityInheritance.All);
            });

            Step("Allow DCs to read each other's Security log (Domain Controllers → Event Log Readers)", () =>
            {
                using var readers = new DirectoryEntry($"LDAP://<SID=S-1-5-32-573>");
                using var dcGroup = new DirectoryEntry($"LDAP://<SID={domainSid}-516>");
                var dcGroupDn = (string)dcGroup.Properties["distinguishedName"].Value!;
                bool already = readers.Properties["member"].Cast<object>().Any(m => string.Equals((string)m, dcGroupDn, StringComparison.OrdinalIgnoreCase));
                if (already) { Console.Write("already member "); return; }
                readers.Properties["member"].Add(dcGroupDn);
                readers.CommitChanges();
                Run("klist.exe", "-li 0x3e7 purge"); // refresh the computer's Kerberos tickets so the new membership applies
            });
        }

        var local = Environment.MachineName;
        var script = """
            auditpol /set /subcategory:"{0CCE923C-69AE-11D9-BED3-505054503030}" /success:enable | Out-Null
            auditpol /set /subcategory:"{0CCE9215-69AE-11D9-BED3-505054503030}" /success:enable | Out-Null
            auditpol /set /subcategory:"{0CCE9235-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable | Out-Null
            auditpol /set /subcategory:"{0CCE9217-69AE-11D9-BED3-505054503030}" /success:enable | Out-Null
            auditpol /set /subcategory:"{0CCE922F-69AE-11D9-BED3-505054503030}" /success:enable | Out-Null
            $log = Get-WinEvent -ListLog Security
            if ($log.MaximumSizeInBytes -lt 1GB) { wevtutil sl Security /ms:1073741824 }
            Get-NetFirewallRule -Group '@FirewallAPI.dll,-29252' -ErrorAction SilentlyContinue | Enable-NetFirewallRule
            """;
        foreach (var dc in dcs.Count > 0 ? dcs : new List<string> { local })
        {
            bool isLocal = dc.Split('.')[0].Equals(local, StringComparison.OrdinalIgnoreCase);
            Step($"Enable auditing, 1 GB Security log, remote event log firewall rule on {dc}", () =>
            {
                var cmd = isLocal ? script : $"Invoke-Command -ComputerName '{dc}' -ErrorAction Stop -ScriptBlock {{\n{script}\n}}";
                Run("powershell.exe", "-NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand " +
                                      Convert.ToBase64String(Encoding.Unicode.GetBytes(cmd)), true);
            });
        }

        Step("Create Start menu shortcut", CreateShortcut);

        Step("Harden service permissions and start service", () =>
        {
            Run("sc.exe", $"sdset {Proto.ServiceName} \"{HardenedSddl}\"", true);
            using var sc = new ServiceController(Proto.ServiceName);
            sc.Start();
            sc.WaitForStatus(ServiceControllerStatus.Running, TimeSpan.FromSeconds(60));
        });

        Console.WriteLine();
        if (Problems.Count == 0)
            Console.WriteLine("Installation complete. Start \"AD Audit Trail\" from the Start menu (administrator only).");
        else
        {
            Console.WriteLine("Installation finished with problems:");
            foreach (var p in Problems) Console.WriteLine("  - " + p);
            Console.WriteLine("\nSee README.md ('Manual configuration') for the equivalent manual steps.");
        }
        Console.WriteLine("\nIMPORTANT: if your Default Domain Controllers Policy defines 'Advanced Audit Policy' settings, add");
        Console.WriteLine("  'DS Access > Audit Directory Service Changes: Success' there, otherwise Group Policy overrides auditpol.");
        Pause(quiet);
        return Problems.Count == 0 ? 0 : 1;
    }

    /// <summary>Admin PC: viewer only. No service, no database — it connects to the DC's service over the network.</summary>
    public static int InstallViewer(bool quiet)
    {
        Native.AllocConsole();
        Console.OutputEncoding = Encoding.UTF8;
        Console.WriteLine("AD Audit Trail – viewer installation (admin workstation)\n");
        Step($"Copy program to {InstallDir}", () =>
        {
            Directory.CreateDirectory(InstallDir);
            var self = Environment.ProcessPath!;
            if (!string.Equals(Path.GetFullPath(self), Path.GetFullPath(ExePath), StringComparison.OrdinalIgnoreCase))
                ReplaceExe(self);
        });
        Step("Create Start menu shortcut", CreateShortcut);
        Console.WriteLine("\nNo local database or service was installed. The viewer connects to the AD Audit service on your");
        Console.WriteLine("domain controllers (\\\\DC\\pipe\\ADAudit.v1 over SMB) with your account or with credentials you enter.");
        Pause(quiet);
        return Problems.Count == 0 ? 0 : 1;
    }

    /// <summary>Works while a viewer is open: a running exe cannot be overwritten, but it can be renamed.</summary>
    static void ReplaceExe(string source)
    {
        var old = ExePath + ".old";
        try { if (File.Exists(old)) File.Delete(old); } catch { /* still in use by an old viewer; harmless */ }
        if (File.Exists(ExePath))
        {
            if (File.Exists(old)) old = ExePath + $".{DateTime.Now:yyyyMMddHHmmss}.old";
            File.Move(ExePath, old);
        }
        File.Copy(source, ExePath, true);
    }

    static void CreateShortcut()
    {
        var shellType = Type.GetTypeFromProgID("WScript.Shell")!;
        dynamic shell = Activator.CreateInstance(shellType)!;
        dynamic lnk = shell.CreateShortcut(Shortcut);
        lnk.TargetPath = ExePath;
        lnk.WorkingDirectory = InstallDir;
        lnk.Description = "AD Audit Trail (requires administrator)";
        lnk.Save();
    }

    public static int Uninstall(bool quiet)
    {
        Native.AllocConsole();
        Console.WriteLine("AD Audit Trail – uninstall\n");
        bool hasService = ServiceController.GetServices().Any(s => s.ServiceName == Proto.ServiceName);
        if (hasService) Step("Stop and delete service", () =>
        {
            Run("sc.exe", $"sdset {Proto.ServiceName} \"{DefaultSddl}\"");
            using (var sc = new ServiceController(Proto.ServiceName))
            {
                if (sc.Status != ServiceControllerStatus.Stopped)
                {
                    sc.Stop();
                    sc.WaitForStatus(ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(60));
                }
            }
            Run("sc.exe", $"delete {Proto.ServiceName}", true);
        });
        Step("Remove Start menu shortcut", () => { if (File.Exists(Shortcut)) File.Delete(Shortcut); });
        if (hasService) Console.WriteLine($"\nThe audit database in {Config.DataDir} was kept on purpose (evidence).");
        Console.WriteLine($"Program files in {InstallDir} can be deleted manually.");
        Pause(quiet);
        return Problems.Count == 0 ? 0 : 1;
    }

    static void AddSacl(string dn, ActiveDirectorySecurityInheritance inheritance)
    {
        using var de = new DirectoryEntry("LDAP://" + dn);
        de.Options!.SecurityMasks = SecurityMasks.Sacl;
        de.RefreshCache(new[] { "nTSecurityDescriptor" });
        var sd = de.ObjectSecurity;
        var everyone = new SecurityIdentifier(WellKnownSidType.WorldSid, null);
        var rights = ActiveDirectoryRights.WriteProperty | ActiveDirectoryRights.CreateChild | ActiveDirectoryRights.DeleteChild |
                     ActiveDirectoryRights.Delete | ActiveDirectoryRights.DeleteTree | ActiveDirectoryRights.WriteDacl |
                     ActiveDirectoryRights.WriteOwner | ActiveDirectoryRights.Self;
        sd.AddAuditRule(new ActiveDirectoryAuditRule(everyone, rights, AuditFlags.Success, inheritance));
        de.CommitChanges();
    }

    static void Step(string name, Action action)
    {
        Console.Write($"  • {name} … ");
        try
        {
            action();
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("OK");
        }
        catch (Exception ex)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine("FAILED");
            Console.ResetColor();
            Console.WriteLine("      " + ex.Message.Trim());
            Problems.Add($"{name}: {ex.Message.Trim()}");
        }
        Console.ResetColor();
    }

    static void Run(string exe, string args, bool throwOnError = false)
    {
        var psi = new ProcessStartInfo(exe, args)
        {
            UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true,
        };
        using var p = Process.Start(psi)!;
        var stdout = p.StandardOutput.ReadToEndAsync();
        var stderr = p.StandardError.ReadToEndAsync();
        p.WaitForExit();
        if (throwOnError && p.ExitCode != 0)
            throw new InvalidOperationException($"{exe} exited with {p.ExitCode}: {(stderr.Result + " " + stdout.Result).Trim()}");
    }

    static void Pause(bool quiet)
    {
        if (quiet) return;
        Console.WriteLine("\nPress Enter to close.");
        Console.ReadLine();
    }
}
