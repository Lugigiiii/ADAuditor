using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Principal;

namespace ADAudit;

public static class Program
{
    [STAThread]
    public static int Main(string[] args)
    {
        var a = args.Select(x => x.Trim().ToLowerInvariant()).ToList();

        // Service mode never touches WPF (keeps the resident process small).
        if (a.Contains("--service"))
        {
            System.ServiceProcess.ServiceBase.Run(new Service.AuditService());
            return 0;
        }

        if (a.Contains("--selftest")) return Service.SelfTest.Run(); // temp database only

        bool demo = a.Contains("--demo");
        if (!demo && !IsElevatedAdmin()) return Denied();

        if (a.Contains("--install")) return Install.Installer.Install(a.Contains("--quiet"));
        if (a.Contains("--install-viewer")) return Install.Installer.InstallViewer(a.Contains("--quiet"));
        if (a.Contains("--uninstall")) return Install.Installer.Uninstall(a.Contains("--quiet"));
        if (a.Contains("--console")) return RunConsole();

        int i = a.IndexOf("--server");
        string? server = i >= 0 && i + 1 < args.Length ? args[i + 1] : null;
        return RunViewer(demo, server);
    }

    [MethodImpl(MethodImplOptions.NoInlining)]
    static int RunViewer(bool demo, string? server) => new UI.AuditApp(demo, server).Run();

    [MethodImpl(MethodImplOptions.NoInlining)]
    static int Denied()
    {
        System.Windows.MessageBox.Show("AD Audit Trail must be run as Administrator.", "AD Audit Trail",
            System.Windows.MessageBoxButton.OK, System.Windows.MessageBoxImage.Stop);
        return 5;
    }

    public static bool IsElevatedAdmin()
    {
        using var id = WindowsIdentity.GetCurrent();
        return new WindowsPrincipal(id).IsInRole(WindowsBuiltInRole.Administrator) || id.IsSystem;
    }

    /// <summary>Runs the collector engine in the foreground (troubleshooting only; stop the service first).</summary>
    static int RunConsole()
    {
        Native.AllocConsole();
        Console.WriteLine("ADAudit engine in console mode. Press Enter to stop.");
        var engine = new Service.Engine();
        engine.Start();
        Console.ReadLine();
        engine.Stop();
        return 0;
    }
}

static class Native
{
    [DllImport("kernel32.dll")] public static extern bool AllocConsole();
}
