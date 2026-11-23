using System.DirectoryServices.ActiveDirectory;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.ServiceProcess;
using System.Text;
using System.Text.Json;
using ADAudit.Shared;
using Microsoft.Win32.SafeHandles;

namespace ADAudit.UI;

/// <summary>Viewer-side settings (per user, no audit data): only the last server.</summary>
public sealed class ViewerSettings
{
    public string? LastServer { get; set; }
    public Dictionary<string, double> ColumnWidths { get; set; } = new();

    static string PathOf => System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "ADAudit", "viewer.json");

    public static ViewerSettings Load()
    {
        try { return JsonSerializer.Deserialize<ViewerSettings>(File.ReadAllText(PathOf)) ?? new(); }
        catch { return new(); }
    }

    public void Save()
    {
        try
        {
            Directory.CreateDirectory(System.IO.Path.GetDirectoryName(PathOf)!);
            File.WriteAllText(PathOf, JsonSerializer.Serialize(this));
        }
        catch { }
    }
}

public static class Connection
{
    /// <summary>The ADAudit service is installed on this machine (viewer running on the DC itself).</summary>
    public static bool LocalServiceInstalled()
    {
        try { return ServiceController.GetServices().Any(s => s.ServiceName == Proto.ServiceName); }
        catch { return false; }
    }

    public static List<string> DiscoverDomainControllers()
    {
        try
        {
            using var d = Domain.GetComputerDomain();
            return d.DomainControllers.Cast<DomainController>().Select(dc => dc.Name).OrderBy(n => n).ToList();
        }
        catch { return new(); }
    }

    public static string CurrentUser()
    {
        using var id = WindowsIdentity.GetCurrent();
        return id.Name;
    }

    // ───────────────────────── alternate credentials (like "runas /netonly") ─────────────────────────

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct CREDUI_INFO
    {
        public int cbSize;
        public IntPtr hwndParent;
        public string pszMessageText;
        public string pszCaptionText;
        public IntPtr hbmBanner;
    }

    [DllImport("credui.dll", CharSet = CharSet.Unicode)]
    static extern int CredUIPromptForWindowsCredentials(ref CREDUI_INFO info, int authError, ref uint authPackage,
        IntPtr inBuffer, uint inSize, out IntPtr outBuffer, out uint outSize, ref bool save, int flags);

    [DllImport("credui.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern bool CredUnPackAuthenticationBuffer(int flags, IntPtr buffer, uint size, StringBuilder user, ref int userLen,
        StringBuilder domain, ref int domainLen, StringBuilder password, ref int passwordLen);

    [DllImport("ole32.dll")] static extern void CoTaskMemFree(IntPtr p);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern bool LogonUser(string user, string? domain, string password, int logonType, int provider, out SafeAccessTokenHandle token);

    /// <summary>
    /// Shows the standard Windows credential dialog and returns a "network-only" logon token for the entered
    /// account (LOGON32_LOGON_NEW_CREDENTIALS). Nothing is stored; the password is not kept.
    /// </summary>
    public static (SafeAccessTokenHandle token, string user)? PromptCredentials(IntPtr owner, string server, string message)
    {
        var info = new CREDUI_INFO
        {
            cbSize = Marshal.SizeOf<CREDUI_INFO>(),
            hwndParent = owner,
            pszCaptionText = "AD Audit Trail",
            pszMessageText = message.Length > 0 ? message : $"Enter domain administrator credentials to view the audit trail on {server}.",
        };
        uint package = 0;
        bool save = false;
        int rc = CredUIPromptForWindowsCredentials(ref info, 0, ref package, IntPtr.Zero, 0, out var buf, out var size, ref save, 0x1 /* GENERIC */);
        if (rc != 0) return null;
        try
        {
            var user = new StringBuilder(256);
            var domain = new StringBuilder(256);
            var pass = new StringBuilder(512);
            int ul = user.Capacity, dl = domain.Capacity, pl = pass.Capacity;
            if (!CredUnPackAuthenticationBuffer(0, buf, size, user, ref ul, domain, ref dl, pass, ref pl)) return null;

            string u = user.ToString(), d = domain.ToString();
            if (d.Length == 0 && u.Contains('\\')) { d = u[..u.IndexOf('\\')]; u = u[(u.IndexOf('\\') + 1)..]; }
            string display = d.Length > 0 ? $"{d}\\{u}" : u;
            // LOGON32_LOGON_NEW_CREDENTIALS = 9, LOGON32_PROVIDER_WINNT50 = 3
            bool ok = LogonUser(u, d.Length > 0 ? d : null, pass.ToString(), 9, 3, out var token);
            pass.Clear();
            for (int i = 0; i < pass.Capacity; i++) pass.Append('\0');
            return ok ? (token, display) : null;
        }
        finally
        {
            // wipe and free the packed buffer
            for (int i = 0; i < size; i++) Marshal.WriteByte(buf, i, 0);
            CoTaskMemFree(buf);
        }
    }
}

/// <summary>
/// Talks to the ADAudit service over its named pipe: locally ("."), or remotely as \\server\pipe\ADAudit.v1
/// (SMB / Kerberos with the current account or the alternate credentials).
/// </summary>
public sealed class PipeSource : IAuditSource
{
    readonly SemaphoreSlim _lock = new(1, 1);
    readonly SafeAccessTokenHandle? _token;
    NamedPipeClientStream? _pipe;
    StreamReader? _reader;
    StreamWriter? _writer;

    public string Server { get; }
    public string? AlternateUser { get; }

    public PipeSource(string server, SafeAccessTokenHandle? token = null, string? alternateUser = null)
    {
        Server = string.IsNullOrWhiteSpace(server) ? "." : server.Trim().TrimStart('\\');
        _token = token;
        AlternateUser = alternateUser;
    }

    void Open()
    {
        void Connect()
        {
            var p = new NamedPipeClientStream(Server, Proto.PipeName, PipeDirection.InOut, PipeOptions.Asynchronous,
                TokenImpersonationLevel.Identification); // lets the service record who is viewing
            p.Connect(Server == "." ? 3000 : 8000);
            _pipe = p;
        }
        if (_token != null) WindowsIdentity.RunImpersonated(_token, Connect);
        else Connect();
        _reader = new StreamReader(_pipe!, new UTF8Encoding(false), false, 1 << 16, leaveOpen: true);
        _writer = new StreamWriter(_pipe!, new UTF8Encoding(false), 1 << 16, leaveOpen: true);
    }

    async Task<PipeResponse> Call(PipeRequest req)
    {
        await _lock.WaitAsync();
        try
        {
            for (int attempt = 0; ; attempt++)
            {
                try
                {
                    if (_pipe is not { IsConnected: true })
                    {
                        Reset();
                        await Task.Run(Open);
                    }
                    await _writer!.WriteLineAsync(JsonSerializer.Serialize(req, Proto.Json));
                    await _writer.FlushAsync();
                    var line = await _reader!.ReadLineAsync() ?? throw new IOException("Service closed the connection.");
                    var resp = JsonSerializer.Deserialize<PipeResponse>(line, Proto.Json)!;
                    if (!resp.Ok) throw new InvalidOperationException(resp.Error);
                    return resp;
                }
                catch (Exception ex) when (attempt == 0 && ex is IOException or ObjectDisposedException)
                {
                    Reset();
                }
                catch (UnauthorizedAccessException)
                {
                    Reset();
                    throw new UnauthorizedAccessException($"Access denied on {Server}: the account must be an administrator of the domain controllers (e.g. Domain Admins).");
                }
                catch (System.TimeoutException)
                {
                    Reset();
                    throw new System.TimeoutException($"No ADAudit service answered on {Server}. Is the service \"AD Audit Trail\" installed and running there?");
                }
            }
        }
        finally { _lock.Release(); }
    }

    void Reset()
    {
        try { _pipe?.Dispose(); } catch { }
        _pipe = null; _reader = null; _writer = null;
    }

    public async Task<QueryResult> QueryAsync(QueryRequest q) => (await Call(new PipeRequest { Op = "query", Query = q })).Query!;
    public async Task<StatusInfo> StatusAsync() => (await Call(new PipeRequest { Op = "status" })).Status!;
    public async Task<VerifyResult> VerifyAsync(bool force) => (await Call(new PipeRequest { Op = "verify", Force = force })).Verify!;
    public async Task<List<GuardItem>> GuardAsync() => (await Call(new PipeRequest { Op = "guard" })).Guard ?? new();
    public async Task<AuditEntry?> GetAsync(long id) => (await Call(new PipeRequest { Op = "get", Id = id })).Entry;
    public async Task<AlertSettings> GetSettingsAsync() => (await Call(new PipeRequest { Op = "settings-get" })).Settings!;
    public async Task<AlertSettings> SaveSettingsAsync(AlertSettings s) => (await Call(new PipeRequest { Op = "settings-set", Settings = s })).Settings!;
    public async Task<string> TestMailAsync(AlertSettings s) => (await Call(new PipeRequest { Op = "settings-testmail", Settings = s })).Message ?? "";
    public async Task<string> AcknowledgeAsync(long guardId, string reason) => (await Call(new PipeRequest { Op = "guard-ack", Id = guardId, Text = reason })).Message ?? "";
    public async Task<List<AckInfo>> AcksAsync() => (await Call(new PipeRequest { Op = "acks-list" })).Acks ?? new();
    public async Task<string> RevokeAckAsync(long ackId) => (await Call(new PipeRequest { Op = "ack-revoke", Id = ackId })).Message ?? "";
    public async Task<DashboardInfo> DashboardAsync(DashboardRequest r) => (await Call(new PipeRequest { Op = "dashboard", Dashboard = r })).Dashboard!;
}
