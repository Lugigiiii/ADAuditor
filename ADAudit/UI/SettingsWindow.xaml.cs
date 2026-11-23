using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Windows;
using System.Windows.Media;
using ADAudit.Shared;

namespace ADAudit.UI;

public sealed class RuleVm : INotifyPropertyChanged
{
    string _name = "";
    bool _alert = true, _autoRemove, _ack;
    string _minutes = "60";

    public int? DomainRid { get; init; }
    public string Name { get => _name; set { _name = value; Changed(nameof(Name)); } }
    public bool Alert { get => _alert; set { _alert = value; Changed(nameof(Alert)); } }
    public bool AutoRemove { get => _autoRemove; set { _autoRemove = value; Changed(nameof(AutoRemove)); Changed(nameof(RemoveText)); } }
    public bool RequireAck { get => _ack; set { _ack = value; Changed(nameof(RequireAck)); Changed(nameof(AckText)); } }
    public string Minutes { get => _minutes; set { _minutes = value; Changed(nameof(Minutes)); } }

    public string RemoveText => AutoRemove ? "yes" : "no — keep member";
    public string AckText => RequireAck ? "required" : "off";
    public Visibility EditVisibility => DomainRid == null ? Visibility.Visible : Visibility.Collapsed;
    public Visibility BuiltInVisibility => DomainRid == null ? Visibility.Collapsed : Visibility.Visible;
    public string BuiltInHint => DomainRid is int rid ? $"built-in group, matched by RID {rid} (any AD language)" : "";

    public event PropertyChangedEventHandler? PropertyChanged;
    void Changed(string p) => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(p));
}

public partial class SettingsWindow : Window
{
    readonly IAuditSource _src;
    readonly ObservableCollection<RuleVm> _rules = new();
    static readonly SolidColorBrush Bad = new(Color.FromRgb(0xFC, 0xA5, 0xA5));
    static readonly SolidColorBrush Good = new(Color.FromRgb(0x86, 0xEF, 0xAC));

    public SettingsWindow(AlertSettings s, IAuditSource src)
    {
        _src = src;
        InitializeComponent();
        SourceInitialized += (_, _) => Glass.Apply(this);
        foreach (var r in s.Rules)
            _rules.Add(new RuleVm
            {
                DomainRid = r.DomainRid, Name = r.Name, Alert = r.Alert, AutoRemove = r.AutoRemove, RequireAck = r.RequireAck,
                Minutes = r.RemoveAfterMinutes.ToString(),
            });
        RulesList.ItemsSource = _rules;
        PopupBox.IsChecked = s.PopupAlerts;
        SmtpHost.Text = s.SmtpHost;
        SmtpPort.Text = s.SmtpPort.ToString();
        SmtpSsl.IsChecked = s.SmtpSsl;
        SmtpUser.Text = s.SmtpUser;
        SmtpFrom.Text = s.SmtpFrom;
        SmtpTo.Text = s.SmtpTo;
        PwHint.Text = s.SmtpHasPassword ? "•••••• stored — type to replace" : "";
        ClearPw.Visibility = s.SmtpHasPassword ? Visibility.Visible : Visibility.Collapsed;
        SmtpPassword.PasswordChanged += (_, _) => PwHint.Visibility = SmtpPassword.Password.Length == 0 ? Visibility.Visible : Visibility.Collapsed;
        Loaded += async (_, _) => await LoadAcks();
    }

    async Task LoadAcks()
    {
        try
        {
            var acks = await _src.AcksAsync();
            AcksList.ItemsSource = acks;
            NoAcks.Visibility = acks.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
        }
        catch (Exception ex) { NoAcks.Text = "Cannot load acknowledgments: " + ex.Message; }
    }

    async void Revoke_Click(object sender, RoutedEventArgs e)
    {
        if (sender is not FrameworkElement { Tag: long id }) return;
        if (MessageBox.Show(this, "Revoke this acknowledgment? The next time this person is added to the group, an alert is raised again.",
                "Revoke acknowledgment", MessageBoxButton.YesNo, MessageBoxImage.Question) != MessageBoxResult.Yes) return;
        try { await _src.RevokeAckAsync(id); await LoadAcks(); }
        catch (Exception ex) { Fail(ex.Message); }
    }

    void Add_Click(object sender, RoutedEventArgs e) =>
        _rules.Add(new RuleVm { Name = "", Alert = true, AutoRemove = false, RequireAck = false, Minutes = "60" });

    void Delete_Click(object sender, RoutedEventArgs e)
    {
        if (sender is FrameworkElement { Tag: RuleVm r }) _rules.Remove(r);
    }

    void Cancel_Click(object sender, RoutedEventArgs e) => DialogResult = false;

    AlertSettings? Collect()
    {
        var rules = new List<GuardRule>();
        foreach (var r in _rules)
        {
            if (r.DomainRid == null && string.IsNullOrWhiteSpace(r.Name)) continue;
            if (!int.TryParse(r.Minutes, out var min) || min < 1 || min > 43200)
            {
                Fail($"{r.Name}: enter the removal time in minutes (1 – 43200).");
                return null;
            }
            rules.Add(new GuardRule
            {
                Name = r.Name.Trim(), DomainRid = r.DomainRid, Alert = r.Alert, AutoRemove = r.AutoRemove,
                RequireAck = r.RequireAck, RemoveAfterMinutes = min,
            });
        }
        if (!int.TryParse(SmtpPort.Text, out var port) || port is < 1 or > 65535) port = 25;
        return new AlertSettings
        {
            Rules = rules,
            PopupAlerts = PopupBox.IsChecked == true,
            SmtpHost = SmtpHost.Text.Trim(),
            SmtpPort = port,
            SmtpSsl = SmtpSsl.IsChecked == true,
            SmtpUser = SmtpUser.Text.Trim(),
            SmtpPasswordNew = SmtpPassword.Password.Length > 0 ? SmtpPassword.Password : null,
            SmtpClearPassword = ClearPw.IsChecked == true,
            SmtpFrom = SmtpFrom.Text.Trim(),
            SmtpTo = SmtpTo.Text.Trim(),
        };
    }

    async void Test_Click(object sender, RoutedEventArgs e)
    {
        var s = Collect();
        if (s == null) return;
        TestBtn.IsEnabled = false;
        TestMsg.Visibility = Visibility.Visible;
        TestMsg.Foreground = (Brush)FindResource("Fg2");
        TestMsg.Text = "Sending test mail from the domain controller…";
        try
        {
            TestMsg.Text = "✓ " + await _src.TestMailAsync(s);
            TestMsg.Foreground = Good;
        }
        catch (Exception ex)
        {
            TestMsg.Text = "✗ " + ex.Message;
            TestMsg.Foreground = Bad;
        }
        finally { TestBtn.IsEnabled = true; }
    }

    async void Save_Click(object sender, RoutedEventArgs e)
    {
        var s = Collect();
        if (s == null) return;
        SaveBtn.IsEnabled = false;
        try
        {
            await _src.SaveSettingsAsync(s);
            DialogResult = true;
        }
        catch (Exception ex) { Fail(ex.Message); }
        finally { SaveBtn.IsEnabled = true; }
    }

    void Fail(string msg)
    {
        Msg.Text = msg;
        Msg.Foreground = Bad;
    }
}
