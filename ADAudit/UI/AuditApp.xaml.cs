using System.Windows;
using System.Windows.Threading;

namespace ADAudit.UI;

public partial class AuditApp : Application
{
    readonly bool _demo;
    readonly string? _server;

    public AuditApp(bool demo, string? server)
    {
        _demo = demo;
        _server = server;
        InitializeComponent();
        DispatcherUnhandledException += OnUnhandled;
    }

    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        var w = new MainWindow(_demo, _server);
        MainWindow = w;
        w.Show();
    }

    static void OnUnhandled(object sender, DispatcherUnhandledExceptionEventArgs e)
    {
        MessageBox.Show(e.Exception.Message, "AD Audit Trail", MessageBoxButton.OK, MessageBoxImage.Error);
        e.Handled = true;
    }
}
