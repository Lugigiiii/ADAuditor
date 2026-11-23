using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Text;
using System.Text.RegularExpressions;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Input;
using System.Windows.Interop;
using System.Windows.Media;
using System.Windows.Threading;
using ADAudit.Shared;
using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;

namespace ADAudit.UI;

public sealed class PillVm
{
    public string Label { get; init; } = "";
    public string Sub { get; init; } = "";
    public string Dot { get; init; } = "#3FB950";
    public string Tip { get; init; } = "";
}

public sealed class LegendVm
{
    public string Name { get; init; } = "";
    public string Text { get; init; } = "";
    public Brush Color { get; init; } = Brushes.Gray;
}

public sealed class GuardVm : INotifyPropertyChanged
{
    public GuardItem Item { get; }
    public GuardVm(GuardItem item) => Item = item;
    public long AuditId => Item.AuditId;
    bool Pending => Item.Status == GuardStatus.Pending;
    bool AlertOnly => Item.Status is GuardStatus.AlertOnly or GuardStatus.Unacknowledged;
    public string Icon => Pending || AlertOnly ? "\uE7BA" : Item.Status == GuardStatus.Failed ? "\uEA39" : "\uE73E";
    public string Background => Pending || Item.Status == GuardStatus.Failed ? "#59B62324" : AlertOnly ? "#4DB7791F" : "#2E3FB950";
    public string Border => Pending || Item.Status == GuardStatus.Failed ? "#C0F85149" : AlertOnly ? "#C0D29922" : "#803FB950";
    public Visibility AckVisibility => Item.Ackable && Item.Status is GuardStatus.Unacknowledged or GuardStatus.Pending or GuardStatus.AlertOnly
        ? Visibility.Visible : Visibility.Collapsed;
    public long GuardId => Item.Id;

    public string Text
    {
        get
        {
            var who = Dn.FriendlyName(Item.MemberDn);
            var at = Item.AddedUtc.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss");
            return Item.Status switch
            {
                GuardStatus.Pending => $"{who} was added to {Item.GroupName} by {Item.AddedBy} at {at}.  Automatic removal at {Item.DueUtc.ToLocalTime():HH:mm:ss}.",
                GuardStatus.Removed => $"{who} was added to {Item.GroupName} by {Item.AddedBy} at {at} and removed automatically at {Item.StatusUtc?.ToLocalTime():HH:mm:ss}.",
                GuardStatus.AlreadyRemoved => $"{who} was added to {Item.GroupName} by {Item.AddedBy} at {at}; membership was already gone at the deadline.",
                GuardStatus.AlertOnly => $"{who} was added to {Item.GroupName} by {Item.AddedBy} at {at}.  {Item.Message ?? "Alert only."}",
                GuardStatus.Unacknowledged => $"{who} was added to {Item.GroupName} by {Item.AddedBy} at {at}.  Not acknowledged yet — is this membership intended?",
                GuardStatus.Acknowledged => $"{who} in {Item.GroupName}: {Item.Message}",
                _ => $"Automatic removal of {who} from {Item.GroupName} FAILED: {Item.Message} — remove manually!",
            };
        }
    }

    public string Countdown
    {
        get
        {
            if (!Pending) return Item.Status == GuardStatus.Failed ? "ACTION NEEDED" : "";
            var left = Item.DueUtc - DateTime.UtcNow;
            return left <= TimeSpan.Zero ? "removing…" : $"{(int)left.TotalMinutes:00}:{left.Seconds:00}";
        }
    }

    public void Tick() => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(Countdown)));
    public event PropertyChangedEventHandler? PropertyChanged;
}

public partial class MainWindow : Window
{
    const int PageSize = 1500;

    readonly bool _demo;
    readonly string? _serverArg;
    IAuditSource? _src;
    readonly ObservableCollection<AuditEntry> _items = new();
    readonly ObservableCollection<PillVm> _pills = new();
    readonly ObservableCollection<GuardVm> _guards = new();
    readonly Dictionary<string, ToggleButton> _chips = new();
    readonly DispatcherTimer _debounce = new() { Interval = TimeSpan.FromMilliseconds(350) };
    readonly DispatcherTimer _clock = new() { Interval = TimeSpan.FromSeconds(1) };
    List<EventGroup> _groups = new();
    StatusInfo? _status;
    VerifyResult? _verify;
    bool _loading, _ready, _dashLoading;
    long _total;
    int _ticks, _dashDays = 30;

    public MainWindow(bool demo, string? server)
    {
        _demo = demo;
        _serverArg = server;
        InitializeComponent();
        DemoBadge.Visibility = demo ? Visibility.Visible : Visibility.Collapsed;
        Results.ItemsSource = _items;
        Pills.ItemsSource = _pills;
        GuardList.ItemsSource = _guards;

        foreach (var c in Cat.All)
        {
            var chip = new ToggleButton { Content = c, Tag = Hex(Cat.Color(c)), Style = (Style)FindResource("Chip") };
            chip.Checked += Filter_Changed;
            chip.Unchecked += Filter_Changed;
            _chips[c] = chip;
            Chips.Children.Add(chip);
        }
        var clear = new Button { Content = "All categories", Style = (Style)FindResource("GlassButton"), Padding = new Thickness(10, 3, 10, 3) };
        clear.Click += (_, _) => { _ready = false; foreach (var ch in _chips.Values) ch.IsChecked = false; _ready = true; _ = Reload(); };
        Chips.Children.Add(clear);

        DcBox.Items.Add("All DCs");
        DcBox.SelectedIndex = 0;
        FromDate.SelectedDate = DateTime.Today.AddDays(-7);
        ToDate.SelectedDate = DateTime.Today;
        RangeBox.SelectedIndex = 4; // half a year
        ShowDetail(null);

        SourceInitialized += (_, _) => Glass.Apply(this);
        StateChanged += (_, _) =>
        {
            Root.Margin = WindowState == WindowState.Maximized ? new Thickness(7) : new Thickness(0);
            MaxBtn.Content = WindowState == WindowState.Maximized ? "" : "";
        };
        _debounce.Tick += async (_, _) => { _debounce.Stop(); await Reload(); };
        _clock.Tick += async (_, _) => await OnClock();
        PreviewKeyDown += OnKey;
        Loaded += async (_, _) => await StartupConnect();

        // revert connectors in the timeline gutter follow scrolling, resizing and list changes
        Results.AddHandler(ScrollViewer.ScrollChangedEvent, new ScrollChangedEventHandler((_, _) => QueueLinks()));
        Results.SizeChanged += (_, _) => QueueLinks();
        _items.CollectionChanged += (_, _) => QueueLinks();
        Results.Sorting += (_, _) => QueueLinks();

        // remembered column widths (per user, viewer.json)
        var widths = ViewerSettings.Load().ColumnWidths;
        foreach (var col in Results.Columns)
            if (col.Header is string h && widths.TryGetValue(h, out var w) && !col.Width.IsStar && w > 20) col.Width = new DataGridLength(w);
        Closing += (_, _) =>
        {
            var s = ViewerSettings.Load();
            foreach (var col in Results.Columns)
                if (col.Header is string h && !col.Width.IsStar) s.ColumnWidths[h] = col.ActualWidth;
            s.Save();
        };
    }

    static SolidColorBrush Hex(string hex, byte alpha = 0xFF)
    {
        var c = (Color)ColorConverter.ConvertFromString(hex);
        c.A = alpha;
        return new SolidColorBrush(c);
    }

    // ═════════════════════════ connection ═════════════════════════

    async Task StartupConnect()
    {
        if (_demo) { await Attach(new DemoSource(), "DEMO"); return; }
        if (_serverArg != null) { if (await TryConnect(_serverArg, null, null)) return; ShowConnect(); return; }
        if (Connection.LocalServiceInstalled() && await TryConnect(".", null, null)) return;

        var settings = ViewerSettings.Load();
        if (settings.LastServer != null && await TryConnect(settings.LastServer, null, null, quiet: true)) return;

        ShowConnect("Searching for the AD Audit service on your domain controllers…");
        var dcs = await Task.Run(Connection.DiscoverDomainControllers);
        FillServers(dcs);
        foreach (var dc in dcs)
            if (await TryConnect(dc, null, null, quiet: true)) return;
        ConnectMsg.Text = dcs.Count == 0
            ? "No domain controllers found automatically. Enter the name of the domain controller running the AD Audit service."
            : "Could not open the audit trail with your current account. Choose the domain controller with the service, or use other credentials (e.g. your Domain Admin account).";
        ConnectMsg.Visibility = Visibility.Visible;
    }

    void FillServers(IEnumerable<string> dcs)
    {
        var current = ServerBox.Text;
        foreach (var dc in dcs) if (!ServerBox.Items.Contains(dc)) ServerBox.Items.Add(dc);
        if (string.IsNullOrWhiteSpace(current) && ServerBox.Items.Count > 0) ServerBox.SelectedIndex = 0;
    }

    void ShowConnect(string? message = null)
    {
        CurrentUserText.Text = $"Current account: {Connection.CurrentUser()}";
        ConnectMsg.Text = message ?? "";
        ConnectMsg.Foreground = message != null && message.StartsWith("Searching") ? (Brush)FindResource("Fg2") : Hex("#FCA5A5");
        ConnectMsg.Visibility = string.IsNullOrEmpty(message) ? Visibility.Collapsed : Visibility.Visible;
        ConnectCancel.Visibility = _src != null ? Visibility.Visible : Visibility.Collapsed;
        var last = ViewerSettings.Load().LastServer;
        if (string.IsNullOrWhiteSpace(ServerBox.Text) && last != null) ServerBox.Text = last;
        ConnectOverlay.Visibility = Visibility.Visible;
    }

    async Task<bool> TryConnect(string server, SafeAccessTokenHandle? token, string? user, bool quiet = false)
    {
        ConnectBtn.IsEnabled = ConnectAltBtn.IsEnabled = false;
        try
        {
            var src = new PipeSource(server, token, user);
            await src.StatusAsync();
            if (server != ".") { var s = ViewerSettings.Load(); s.LastServer = server; s.Save(); }
            await Attach(src, server == "." ? Environment.MachineName : server.ToUpperInvariant());
            return true;
        }
        catch (Exception ex)
        {
            if (!quiet)
            {
                ShowConnect(ex.Message);
                if (ex is UnauthorizedAccessException) ConnectMsg.Text += "\nTry \"Use other credentials…\" with your Domain Admin account.";
            }
            return false;
        }
        finally { ConnectBtn.IsEnabled = ConnectAltBtn.IsEnabled = true; }
    }

    async Task Attach(IAuditSource src, string label)
    {
        _src = src;
        ConnectOverlay.Visibility = Visibility.Collapsed;
        _ready = true;
        _verify = null;
        if (DashDefault.IsChecked != true) DashDefault.IsChecked = true; else await RefreshDashboard();
        await RefreshStatus();
        await Reload();
        _clock.Start();
        await RunVerify(force: false);
    }

    async void Connect_Click(object sender, RoutedEventArgs e)
    {
        var s = ServerBox.Text.Trim();
        if (s.Length == 0) { ShowConnect("Enter a domain controller name."); return; }
        await TryConnect(s, null, null);
    }

    async void ConnectAlt_Click(object sender, RoutedEventArgs e)
    {
        var s = ServerBox.Text.Trim();
        if (s.Length == 0) { ShowConnect("Enter a domain controller name first."); return; }
        var cred = Connection.PromptCredentials(new WindowInteropHelper(this).Handle, s, "");
        if (cred == null) return;
        if (!await TryConnect(s, cred.Value.token, cred.Value.user))
            ConnectMsg.Text = $"Signing in as {cred.Value.user} failed: {ConnectMsg.Text}";
    }

    void ConnectCancel_Click(object sender, RoutedEventArgs e) => ConnectOverlay.Visibility = Visibility.Collapsed;

    async void Ack_Click(object sender, RoutedEventArgs e)
    {
        if (_src == null || sender is not FrameworkElement { DataContext: GuardVm vm }) return;
        var dlg = new AckWindow(vm.Item, _src) { Owner = this };
        if (dlg.ShowDialog() == true) await RefreshStatus();
    }

    async void Settings_Click(object sender, RoutedEventArgs e)
    {
        if (_src == null) return;
        try
        {
            var current = await _src.GetSettingsAsync();
            var dlg = new SettingsWindow(current, _src) { Owner = this };
            if (dlg.ShowDialog() == true) await RefreshStatus();
        }
        catch (Exception ex) { ShowError("Settings: " + ex.Message); }
    }

    async void ShowConnect_Click(object sender, RoutedEventArgs e)
    {
        ShowConnect();
        FillServers(await Task.Run(Connection.DiscoverDomainControllers));
    }

    // ═════════════════════════ navigation ═════════════════════════

    void Nav_Checked(object sender, RoutedEventArgs e)
    {
        if (DashboardPage == null) return;
        bool dash = NavDashboard.IsChecked == true;
        DashboardPage.Visibility = dash ? Visibility.Visible : Visibility.Collapsed;
        LogPage.Visibility = dash ? Visibility.Collapsed : Visibility.Visible;
        if (dash) _ = RefreshDashboard(); else QueueLinks();
    }

    void ShowLog() => NavLog.IsChecked = true;

    // ═════════════════════════ dashboard ═════════════════════════

    async void DashRange_Checked(object sender, RoutedEventArgs e)
    {
        if (sender is RadioButton { Tag: string t } && int.TryParse(t, out var d)) _dashDays = d;
        await RefreshDashboard();
    }

    async Task RefreshDashboard()
    {
        if (_src == null || _dashLoading) return;
        _dashLoading = true;
        try
        {
            var to = DateTime.UtcNow;
            var from = to.AddDays(-_dashDays);
            int buckets = _dashDays switch { 1 => 24, 7 => 28, 30 => 30, _ => 26 };
            var d = await _src.DashboardAsync(new DashboardRequest { FromUtc = from, ToUtc = to, Buckets = buckets });

            DashSubtitle.Text = $"Everything that changed in Active Directory · {(_dashDays == 1 ? "last 24 hours" : _dashDays == 183 ? "last 6 months" : $"last {_dashDays} days")} · {d.Total:N0} entries";
            StatChanges.Text = d.DirectoryChanges.ToString("N0");
            StatMembership.Text = d.Membership.ToString("N0");
            StatMembershipSub.Text = "members added / removed";
            StatCreated.Text = d.CreatedDeleted.ToString("N0");
            StatReverted.Text = d.Reverted.ToString("N0");
            StatSecurity.Text = d.SecurityEvents.ToString("N0");
            StatAlerts.Text = (d.Alerts + d.Tamper).ToString("N0");
            StatAlertsSub.Text = $"{d.Alerts:N0} guard alerts · {d.Tamper:N0} tampering";
            AlertCard.BorderBrush = d.Tamper > 0 ? Hex("#F85149") : (Brush)((Style)FindResource("GlassPanel")).Setters.OfType<Setter>().First(s => s.Property == Border.BorderBrushProperty).Value;

            string fmt = _dashDays == 1 ? "HH:mm" : "dd.MM.";
            var labels = d.Series.Select(p => p.StartUtc.ToLocalTime().ToString(fmt)).ToArray();
            var a = d.Series.Select(p => (double)p.Changes).ToArray();
            var b = d.Series.Select(p => (double)p.Security).ToArray();
            ActivityChart.SetData(a, b, labels);
            SparkChanges.ColorA = (Color)ColorConverter.ConvertFromString("#2DD4BF");
            SparkChanges.SetData(a, null, labels);
            SparkSecurity.ColorA = (Color)ColorConverter.ConvertFromString("#F472B6");
            SparkSecurity.SetData(b, null, labels);

            var top = d.Categories.Take(6).ToList();
            long rest = d.Categories.Skip(6).Sum(c => c.Count);
            var slices = top.Select(c => ((double)c.Count, (Color)ColorConverter.ConvertFromString(Cat.Color(c.Name)))).ToList();
            if (rest > 0) slices.Add((rest, Colors.SlateGray));
            Donut.SetData(slices, d.Total.ToString("N0"), "entries");
            DonutLegend.ItemsSource = top.Select(c => new LegendVm
            {
                Name = c.Name, Color = Hex(Cat.Color(c.Name)),
                Text = d.Total == 0 ? "" : $"{c.Count:N0} · {100.0 * c.Count / d.Total:0}%",
            }).Concat(rest > 0 ? new[] { new LegendVm { Name = "Other", Color = Brushes.SlateGray, Text = $"{rest:N0}" } } : Array.Empty<LegendVm>()).ToList();

            _groups = d.Groups;
            ApplyGroupFilter();
            HideError();
        }
        catch (Exception ex) { ShowError(ex.Message); }
        finally { _dashLoading = false; }
    }

    void ApplyGroupFilter()
    {
        var f = GroupFilter.Text.Trim();
        GroupFilterHint.Visibility = f.Length == 0 ? Visibility.Visible : Visibility.Collapsed;
        Groups.ItemsSource = f.Length == 0 ? _groups : _groups.Where(g =>
            $"{g.Action} {g.Actor} {g.Targets} {g.Category} {g.Attribute}".Contains(f, StringComparison.OrdinalIgnoreCase)).ToList();
    }

    void GroupFilter_TextChanged(object sender, TextChangedEventArgs e) => ApplyGroupFilter();

    async void Groups_DoubleClick(object sender, MouseButtonEventArgs e) => await OpenGroup();
    async void Groups_KeyDown(object sender, KeyEventArgs e) { if (e.Key == Key.Enter) { e.Handled = true; await OpenGroup(); } }

    /// <summary>Drill down: show the individual entries of a group in the log.</summary>
    async Task OpenGroup()
    {
        if (Groups.SelectedItem is not EventGroup g) return;
        _ready = false;
        foreach (var (name, chip) in _chips) chip.IsChecked = name == g.Category;
        RangeBox.SelectedIndex = _dashDays switch { 1 => 1, 7 => 2, 30 => 3, _ => 4 };
        CustomPanel.Visibility = Visibility.Collapsed;
        SearchBox.Text = $"\"{g.Actor}\" \"{g.Action}\"" + (g.Attribute.Length > 0 ? $" \"{g.Attribute}\"" : "");
        _debounce.Stop();
        _ready = true;
        ShowLog();
        await Reload();
    }

    // ═════════════════════════ log querying ═════════════════════════

    QueryRequest BuildQuery()
    {
        var now = DateTime.UtcNow;
        DateTime? from = null, to = null;
        switch (RangeBox.SelectedIndex)
        {
            case 0: from = now.AddHours(-1); break;
            case 1: from = now.AddDays(-1); break;
            case 2: from = now.AddDays(-7); break;
            case 3: from = now.AddDays(-30); break;
            case 4: from = now.AddDays(-183); break;
            case 6:
                from = Combine(FromDate.SelectedDate, FromTime.Text, TimeSpan.Zero);
                to = Combine(ToDate.SelectedDate, ToTime.Text, new TimeSpan(23, 59, 59));
                break;
        }
        return new QueryRequest
        {
            Text = SearchBox.Text.Trim(),
            FromUtc = from,
            ToUtc = to,
            Categories = _chips.Where(c => c.Value.IsChecked == true).Select(c => c.Key).ToList(),
            Dc = DcBox.SelectedIndex > 0 ? DcBox.SelectedItem as string : null,
            OnlyReverted = RevertedOnly.IsChecked == true,
            IncludeNoise = NoiseBox.IsChecked == true,
            Limit = PageSize,
        };
    }

    static DateTime? Combine(DateTime? date, string time, TimeSpan fallback)
    {
        if (date == null) return null;
        var t = TimeSpan.TryParse(time, out var parsed) ? parsed : fallback;
        if (t.Seconds == 0 && fallback.Seconds == 59) t = t.Add(TimeSpan.FromSeconds(59));
        return DateTime.SpecifyKind(date.Value.Date + t, DateTimeKind.Local).ToUniversalTime();
    }

    async Task Reload(bool append = false)
    {
        if (_loading || !_ready || _src == null) return;
        _loading = true;
        try
        {
            var q = BuildQuery();
            if (append && _items.Count > 0)
            {
                var last = _items[^1];
                q.BeforeTicks = last.TimeUtc.Ticks;
                q.BeforeId = last.Id;
            }
            var selected = (Results.SelectedItem as AuditEntry)?.Id;
            var res = await _src.QueryAsync(q);
            if (!append)
            {
                _items.Clear();
                if (Results.Items.Count > 0) Results.ScrollIntoView(Results.Items[0]);
            }
            foreach (var e in res.Items) _items.Add(e);
            _total = res.TotalMatches;
            if (selected.HasValue) Results.SelectedItem = _items.FirstOrDefault(e => e.Id == selected);
            if (Results.SelectedItem == null) ShowDetail(null);
            UpdateFooter();
            HideError();
        }
        catch (Exception ex) { ShowError(ex.Message); }
        finally { _loading = false; }
    }

    /// <summary>Live mode: merge new / changed entries without losing scroll position or selection.</summary>
    async Task LiveMerge()
    {
        if (_loading || !_ready || _src == null) return;
        _loading = true;
        try
        {
            var q = BuildQuery();
            q.Limit = 300;
            var res = await _src.QueryAsync(q);
            var byId = _items.Select((e, i) => (e, i)).ToDictionary(x => x.e.Id, x => x.i);
            foreach (var e in res.Items.AsEnumerable().Reverse())
            {
                if (byId.TryGetValue(e.Id, out var idx))
                {
                    var old = _items[idx];
                    if (old.RevertedById != e.RevertedById || old.RevertsId != e.RevertsId)
                    {
                        bool wasSelected = Results.SelectedItem == old;
                        _items[idx] = e;
                        if (wasSelected) Results.SelectedItem = e;
                    }
                    continue;
                }
                int pos = 0;
                while (pos < _items.Count && (_items[pos].TimeUtc > e.TimeUtc || (_items[pos].TimeUtc == e.TimeUtc && _items[pos].Id > e.Id))) pos++;
                if (pos >= _items.Count && _items.Count >= PageSize) continue;
                _items.Insert(pos, e);
                byId = _items.Select((x, i) => (x, i)).ToDictionary(x => x.x.Id, x => x.i);
            }
            _total = Math.Max(_total, res.TotalMatches);
            UpdateFooter();
            HideError();
        }
        catch (Exception ex) { ShowError(ex.Message); }
        finally { _loading = false; }
    }

    void UpdateFooter()
    {
        StatusText.Text = $"{_items.Count:N0} of {_total:N0} matching entries · updated {DateTime.Now:HH:mm:ss}";
        MoreBtn.Visibility = _items.Count < _total ? Visibility.Visible : Visibility.Collapsed;
    }

    async Task OnClock()
    {
        _ticks++;
        foreach (var g in _guards) g.Tick();
        if (_ticks % 10 == 0)
        {
            await RefreshStatus();
            if (LiveBox.IsChecked == true && LogPage.Visibility == Visibility.Visible) await LiveMerge();
        }
        if (_ticks % 30 == 0 && DashboardPage.Visibility == Visibility.Visible) await RefreshDashboard();
        if (_ticks % 600 == 0) await RunVerify(force: false);
    }

    async Task RefreshStatus()
    {
        if (_src == null) return;
        try
        {
            _status = await _src.StatusAsync();
            HostText.Text = $"{_status.Host} · {_status.TotalEntries:N0} entries · since {_status.OldestUtc?.ToLocalTime():yyyy-MM-dd}" +
                            (_status.Caller != null ? $" · signed in as {_status.Caller}" : "");
            var dcSel = DcBox.SelectedItem as string;
            foreach (var dc in _status.Dcs.Select(d => d.Name))
                if (!DcBox.Items.Contains(dc)) DcBox.Items.Add(dc);
            if (dcSel != null) DcBox.SelectedItem = dcSel;

            bool init = _status.Phase != "Live";
            InitBanner.Visibility = init ? Visibility.Visible : Visibility.Collapsed;
            if (init)
            {
                InitText.Text = _status.PhaseDetail ?? (_status.Phase == "Backfill" ? "Reading historic Security log events…" : "Reconstructing AD history…");
                InitProgress.Value = _status.PhaseProgress ?? 0;
                InitProgress.IsIndeterminate = _status.PhaseProgress == null;
            }

            var guards = await _src.GuardAsync();
            var visible = guards.Where(g => g.Status is GuardStatus.Pending or GuardStatus.Failed or GuardStatus.Unacknowledged ||
                                            (g.StatusUtc ?? g.AddedUtc) > DateTime.UtcNow.AddHours(-2)).ToList();
            if (visible.Count != _guards.Count || visible.Zip(_guards).Any(p => p.First.Id != p.Second.Item.Id || p.First.Status != p.Second.Item.Status || p.First.Ackable != p.Second.Item.Ackable))
            {
                _guards.Clear();
                foreach (var g in visible) _guards.Add(new GuardVm(g));
            }
            if (_status.Warnings.Count > 0) ShowError(string.Join("   •   ", _status.Warnings));
            UpdatePills();
        }
        catch (Exception ex) { ShowError(ex.Message); }
    }

    void UpdatePills()
    {
        _pills.Clear();
        if (_status != null)
        {
            foreach (var dc in _status.Dcs)
            {
                var age = dc.LastPollUtc.HasValue ? DateTime.UtcNow - dc.LastPollUtc.Value : (TimeSpan?)null;
                bool stale = age == null || age > TimeSpan.FromMinutes(2);
                _pills.Add(new PillVm
                {
                    Label = dc.Name,
                    Sub = !dc.Ok ? "unreachable" : stale ? "stale" : dc.IsLocal ? "local · live" : "remote · live",
                    Dot = !dc.Ok ? "#F85149" : stale ? "#D29922" : "#3FB950",
                    Tip = $"{dc.Fqdn}\nLast poll: {dc.LastPollUtc?.ToLocalTime():HH:mm:ss}\nLast record: {dc.LastRecordId:N0}" +
                          (dc.LastError != null ? $"\nError: {dc.LastError}" : ""),
                });
            }
            _pills.Add(new PillVm
            {
                Label = "Service", Sub = $"{_status.ServiceMemoryMb:0} MB", Dot = "#2DD4BF",
                Tip = $"ADAudit service on {_status.Host} (version {_status.Version})\nPrivate memory: {_status.ServiceMemoryMb:0.0} MB\n" +
                      $"CPU time since start: {_status.ServiceCpuSeconds:0.0} s\nRunning since {_status.ServiceStartedUtc.ToLocalTime():yyyy-MM-dd HH:mm}",
            });
        }
        _pills.Add(_verify == null
            ? new PillVm { Label = "Integrity", Sub = "checking…", Dot = "#8B949E", Tip = "Hash chain verification running" }
            : new PillVm
            {
                Label = "Integrity",
                Sub = _verify.Ok ? $"✓ verified {_verify.VerifiedUtc.ToLocalTime():HH:mm}" : "✗ TAMPERED",
                Dot = _verify.Ok ? "#3FB950" : "#F85149",
                Tip = _verify.Message,
            });
    }

    async Task RunVerify(bool force)
    {
        if (_src == null) return;
        VerifyBtn.IsEnabled = false;
        try
        {
            _verify = null;
            UpdatePills();
            _verify = await _src.VerifyAsync(force);
            UpdatePills();
            if (!_verify.Ok) ShowError("INTEGRITY CHECK FAILED: " + _verify.Message);
        }
        catch (Exception ex) { ShowError(ex.Message); }
        finally { VerifyBtn.IsEnabled = true; }
    }

    void ShowError(string msg) { ErrorText.Text = msg; ErrorBanner.Visibility = Visibility.Visible; }
    void HideError()
    {
        if (_verify is { Ok: false } || _status is { Warnings.Count: > 0 }) return;
        ErrorBanner.Visibility = Visibility.Collapsed;
    }

    // ═════════════════════════ details pane ═════════════════════════

    void ShowDetail(AuditEntry? e)
    {
        Detail.Children.Clear();
        if (e == null)
        {
            Detail.Children.Add(new TextBlock
            {
                Text = "Select an entry to see who changed what, when, from where — and whether it was reverted.",
                Foreground = (Brush)FindResource("Fg2"), TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 8, 0, 0),
            });
            return;
        }

        var head = new StackPanel { Orientation = Orientation.Horizontal };
        head.Children.Add(new Border
        {
            CornerRadius = new CornerRadius(10), Padding = new Thickness(9, 2, 9, 3), Margin = new Thickness(0, 0, 8, 0),
            Background = Hex(e.CategoryColor, 0x40),
            Child = new TextBlock { Text = e.Category, FontSize = 11, FontWeight = FontWeights.SemiBold, Foreground = Hex(e.CategoryColor) },
        });
        var src = e.IsReconstructed ? " · reconstructed from AD metadata" : e.EventId > 0 ? $" · Event {e.EventId}" : " · ADAudit";
        head.Children.Add(new TextBlock { Text = $"#{e.Id}{src}", Foreground = (Brush)FindResource("Fg2"), FontSize = 12, VerticalAlignment = VerticalAlignment.Center });
        Detail.Children.Add(head);
        Detail.Children.Add(new TextBlock { Text = e.Action, FontSize = 20, FontWeight = FontWeights.SemiBold, TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 10, 0, 2) });
        Detail.Children.Add(new TextBlock { Text = e.TimeUtc.ToLocalTime().ToString("dddd, yyyy-MM-dd HH:mm:ss") + $"   ({e.TimeUtc:HH:mm:ss} UTC)", Foreground = (Brush)FindResource("Fg2") });

        if (e.IsReconstructed)
            Detail.Children.Add(new Border
            {
                Margin = new Thickness(0, 10, 0, 0), Padding = new Thickness(12, 8, 12, 8), CornerRadius = new CornerRadius(8),
                Background = Hex("#D29922", 0x22), BorderBrush = Hex("#D29922", 0x66), BorderThickness = new Thickness(1),
                Child = new TextBlock
                {
                    TextWrapping = TextWrapping.Wrap, Foreground = Hex("#F2CC60"),
                    Text = "Imported during initialization from AD replication metadata. AD keeps when and on which DC this happened, but not who did it or from where.",
                },
            });

        if (e.RevertedById.HasValue)
        {
            var delay = e.RevertedAtUtc.HasValue ? Human(e.RevertedAtUtc.Value - e.TimeUtc) : "";
            AddLink($"↩  Reverted by #{e.RevertedById} — {e.RevertedByActor}, {e.RevertedAtUtc?.ToLocalTime():yyyy-MM-dd HH:mm:ss} ({delay} later)", e.RevertedById.Value, "#E3B341");
        }
        if (e.RevertsId.HasValue)
            AddLink($"↺  This undoes #{e.RevertsId} from {e.RevertsTimeUtc?.ToLocalTime():yyyy-MM-dd HH:mm:ss}  ({e.LinkKind})", e.RevertsId.Value, "#56D364");
        if (e.Category == Cat.Guard && Regex.Match(e.Details, @"entry #(\d+)") is { Success: true } m)
            AddLink($"→  Show triggering change #{m.Groups[1].Value}", long.Parse(m.Groups[1].Value), "#5EEAD4");

        Section("WHO");
        Field("Actor", e.Actor);
        Field("SID", e.ActorSid);
        Field("Logon ID", e.LogonId);

        Section("FROM WHERE");
        Field("Source", e.Where.Length > 0 ? e.Where : "(not resolvable — logon event no longer in log)");
        Field("Written on DC", e.Dc);

        Section("TARGET");
        Field("Name", e.TargetName);
        Field("DN", e.TargetDn);
        Field("Class", e.TargetClass);
        Field("GUID", e.TargetGuid);

        if (e.Attribute.Length > 0 || e.OldValue.Length > 0 || e.NewValue.Length > 0)
        {
            Section("WHAT CHANGED");
            Field("Attribute", e.Attribute);
            bool member = e.Attribute.Equals("member", StringComparison.OrdinalIgnoreCase);
            ValueBox(member ? "Removed" : "Old value", e.OldShown, "#F85149");
            ValueBox(member ? "Added" : e.IsReconstructed ? "Value today" : "New value", e.NewShown, "#3FB950");
        }

        Section("RAW EVENT DATA");
        Detail.Children.Add(new TextBox
        {
            Text = e.Details, Style = (Style)FindResource("SelectableText"), FontFamily = (FontFamily)FindResource("Mono"), FontSize = 12,
            Background = new SolidColorBrush(Color.FromArgb(0x40, 0, 0, 0)), Padding = new Thickness(10, 8, 10, 8),
        });

        Section("INTEGRITY");
        Field("Source key", e.SourceKey);
        Field("Hash", e.Hash, mono: true);
        Field("Prev. hash", e.PrevHash, mono: true);
    }

    static string Human(TimeSpan t) =>
        t.TotalMinutes < 1 ? $"{t.Seconds}s" : t.TotalHours < 1 ? $"{(int)t.TotalMinutes} min" : t.TotalDays < 1 ? $"{t.TotalHours:0.#} h" : $"{t.TotalDays:0.#} days";

    void Section(string title) => Detail.Children.Add(new TextBlock { Text = title, Style = (Style)FindResource("SectionLabel") });

    void Field(string label, string value, bool mono = false)
    {
        if (string.IsNullOrEmpty(value)) return;
        var g = new Grid { Margin = new Thickness(0, 2, 0, 2) };
        g.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(96) });
        g.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        g.Children.Add(new TextBlock { Text = label, Foreground = (Brush)FindResource("Fg2") });
        var tb = new TextBox { Text = value, Style = (Style)FindResource("SelectableText") };
        if (mono) { tb.FontFamily = (FontFamily)FindResource("Mono"); tb.FontSize = 11.5; }
        Grid.SetColumn(tb, 1);
        g.Children.Add(tb);
        Detail.Children.Add(g);
    }

    void ValueBox(string label, string value, string color)
    {
        if (string.IsNullOrEmpty(value)) return;
        Detail.Children.Add(new TextBlock { Text = label, Foreground = Hex(color), FontSize = 12, FontWeight = FontWeights.SemiBold, Margin = new Thickness(0, 8, 0, 4) });
        Detail.Children.Add(new TextBox
        {
            Text = value, Style = (Style)FindResource("SelectableText"), FontFamily = (FontFamily)FindResource("Mono"), FontSize = 12.5,
            Background = Hex(color, 0x22), Padding = new Thickness(10, 8, 10, 8),
        });
    }

    void AddLink(string text, long id, string color)
    {
        var b = new Button
        {
            Style = (Style)FindResource("LinkButton"),
            Content = new TextBlock { Text = text, TextWrapping = TextWrapping.Wrap, Foreground = Hex(color), FontWeight = FontWeights.SemiBold },
            BorderBrush = Hex(color, 0x70),
            Background = Hex(color, 0x1C),
        };
        b.Click += async (_, _) => await JumpTo(id);
        Detail.Children.Add(b);
    }

    async Task JumpTo(long id)
    {
        ShowLog();
        var hit = _items.FirstOrDefault(x => x.Id == id);
        if (hit != null)
        {
            Results.SelectedItem = hit;
            Results.ScrollIntoView(hit);
            return;
        }
        if (_src == null) return;
        try
        {
            var e = await _src.GetAsync(id);
            Results.SelectedItem = null;
            ShowDetail(e);
        }
        catch (Exception ex) { ShowError(ex.Message); }
    }

    // ═════════════════════════ timeline: revert connectors ═════════════════════════

    bool _linksQueued;

    void QueueLinks()
    {
        if (_linksQueued) return;
        _linksQueued = true;
        Dispatcher.BeginInvoke(DispatcherPriority.Render, () => { _linksQueued = false; DrawLinks(); });
    }

    static T? FindChild<T>(DependencyObject parent) where T : DependencyObject
    {
        for (int i = 0; i < VisualTreeHelper.GetChildrenCount(parent); i++)
        {
            var c = VisualTreeHelper.GetChild(parent, i);
            if (c is T t) return t;
            if (FindChild<T>(c) is { } r) return r;
        }
        return null;
    }

    static readonly SolidColorBrush LinkBrush = Freeze(Hex("#E3B341"));
    static SolidColorBrush Freeze(SolidColorBrush b) { b.Freeze(); return b; }

    /// <summary>
    /// Draws a slim bracket in the timeline gutter between each change and the change that reverted it
    /// (e.g. "member added" ⟷ "member removed"). Pairs get their own lane so they never overlap;
    /// if one end is scrolled out of view the bracket runs to the edge.
    /// </summary>
    void DrawLinks()
    {
        LinkCanvas.Children.Clear();
        if (_items.Count == 0 || LogPage.Visibility != Visibility.Visible || !Results.IsLoaded) return;
        double top = FindChild<DataGridColumnHeadersPresenter>(Results)?.ActualHeight ?? 34;
        double h = LinkCanvas.ActualHeight;
        if (h <= top) return;
        LinkCanvas.Clip = new RectangleGeometry(new Rect(0, top, LinkCanvas.Width, h - top));

        // positions of the rows that are on screen
        var y = new Dictionary<int, double>();
        int first = int.MaxValue, last = -1;
        var view = Results.Items; // honours user sorting
        for (int i = 0; i < view.Count; i++)
        {
            if (Results.ItemContainerGenerator.ContainerFromIndex(i) is not DataGridRow row || !row.IsVisible) continue;
            var p = row.TranslatePoint(new Point(0, row.ActualHeight / 2), LinkCanvas).Y;
            if (p < top - row.ActualHeight || p > h + row.ActualHeight) continue;
            y[i] = p;
            first = Math.Min(first, i);
            last = Math.Max(last, i);
        }
        if (last < 0) return;

        var index = new Dictionary<long, int>();
        for (int i = 0; i < view.Count; i++) if (view[i] is AuditEntry e) index[e.Id] = i;
        var pairs = new List<(int a, int b)>();
        for (int i = 0; i < view.Count; i++)
            if (view[i] is AuditEntry { RevertsId: long other } && index.TryGetValue(other, out var j))
                pairs.Add((Math.Min(i, j), Math.Max(i, j)));
        pairs.Sort((p, q) => p.a.CompareTo(q.a));

        var laneEnd = new List<int>();
        const double node = 14, lane0 = 25, laneGap = 5;
        foreach (var (a, b) in pairs)
        {
            int lane = laneEnd.FindIndex(end => end < a);
            if (lane < 0) { lane = laneEnd.Count; laneEnd.Add(b); } else laneEnd[lane] = b;
            if (b < first || a > last) continue;
            double ya = y.TryGetValue(a, out var v1) ? v1 : top - 6;
            double yb = y.TryGetValue(b, out var v2) ? v2 : h + 6;
            double x = lane0 + Math.Min(lane, 4) * laneGap;
            const double r = 4;
            var g = new StreamGeometry();
            using (var c = g.Open())
            {
                c.BeginFigure(new Point(node + 5, ya), false, false);
                c.LineTo(new Point(x - r, ya), true, true);
                c.QuadraticBezierTo(new Point(x, ya), new Point(x, ya + r), true, true);
                c.LineTo(new Point(x, yb - r), true, true);
                c.QuadraticBezierTo(new Point(x, yb), new Point(x - r, yb), true, true);
                c.LineTo(new Point(node + 5, yb), true, true);
            }
            g.Freeze();
            LinkCanvas.Children.Add(new System.Windows.Shapes.Path
            {
                Data = g, Stroke = LinkBrush, StrokeThickness = 1.5, Opacity = 0.85,
                StrokeLineJoin = PenLineJoin.Round,
            });
            // small arrow head pointing at the reverting (newer) change
            int newer = view[a] is AuditEntry { RevertsId: not null } ? a : b;
            if (y.TryGetValue(newer, out var yn))
                LinkCanvas.Children.Add(new System.Windows.Shapes.Polygon
                {
                    Points = new PointCollection { new(node + 4, yn), new(node + 8.5, yn - 3), new(node + 8.5, yn + 3) },
                    Fill = LinkBrush, Opacity = 0.95,
                });
        }
    }
    // ═════════════════════════ event handlers ═════════════════════════

    void Results_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (Results.SelectedItem is AuditEntry a) ShowDetail(a);
    }

    void Search_TextChanged(object sender, TextChangedEventArgs e)
    {
        SearchHint.Visibility = SearchBox.Text.Length == 0 ? Visibility.Visible : Visibility.Collapsed;
        if (!_ready) return;
        _debounce.Stop();
        _debounce.Start();
    }

    async void Search_KeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.Enter) { _debounce.Stop(); await Reload(); }
    }

    async void OnKey(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.F && Keyboard.Modifiers == ModifierKeys.Control) { ShowLog(); SearchBox.Focus(); SearchBox.SelectAll(); e.Handled = true; }
        else if (e.Key == Key.F5) { e.Handled = true; await RefreshStatus(); await Reload(); await RefreshDashboard(); }
        else if (e.Key == Key.Escape && ConnectOverlay.Visibility == Visibility.Visible && _src != null) { ConnectOverlay.Visibility = Visibility.Collapsed; e.Handled = true; }
        else if (e.Key == Key.Escape && SearchBox.Text.Length > 0) { SearchBox.Clear(); e.Handled = true; }
    }

    async void Range_Changed(object sender, SelectionChangedEventArgs e)
    {
        CustomPanel.Visibility = RangeBox.SelectedIndex == 6 ? Visibility.Visible : Visibility.Collapsed;
        await Reload();
    }

    async void Filter_Changed(object sender, RoutedEventArgs e) => await Reload();
    async void Custom_Changed(object sender, RoutedEventArgs e) { if (RangeBox.SelectedIndex == 6) await Reload(); }
    async void Custom_LostFocus(object sender, RoutedEventArgs e) { if (RangeBox.SelectedIndex == 6) await Reload(); }
    async void Refresh_Click(object sender, RoutedEventArgs e) { await RefreshStatus(); await Reload(); }
    async void More_Click(object sender, RoutedEventArgs e) => await Reload(append: true);
    async void Verify_Click(object sender, RoutedEventArgs e) => await RunVerify(force: true);
    async void GuardShow_Click(object sender, RoutedEventArgs e) { if (sender is FrameworkElement { Tag: long id }) await JumpTo(id); }

    async void Export_Click(object sender, RoutedEventArgs e)
    {
        if (_src == null) return;
        var dlg = new SaveFileDialog { Filter = "CSV (Excel)|*.csv", FileName = $"ad-audit-{DateTime.Now:yyyyMMdd-HHmm}.csv" };
        if (dlg.ShowDialog(this) != true) return;
        try
        {
            Cursor = Cursors.Wait;
            var q = BuildQuery();
            q.Limit = 5000;
            long written = 0;
            await using var w = new StreamWriter(dlg.FileName, false, new UTF8Encoding(true));
            await w.WriteLineAsync("Id;TimeLocal;TimeUtc;Category;Action;Actor;ActorSid;SourceHost;SourceIp;DC;TargetDn;TargetClass;Attribute;OldValue;NewValue;RevertedBy;Reverts;Reconstructed;Hash");
            while (true)
            {
                var res = await _src.QueryAsync(q);
                foreach (var x in res.Items)
                {
                    await w.WriteLineAsync(string.Join(';', new object?[]
                    {
                        x.Id, x.WhenLocal, x.TimeUtc.ToString("o"), x.Category, x.Action, x.Actor, x.ActorSid, x.SourceHost, x.SourceIp, x.Dc,
                        x.TargetDn, x.TargetClass, x.Attribute, x.OldValue, x.NewValue, x.RevertedById, x.RevertsId, x.IsReconstructed ? "yes" : "", x.Hash,
                    }.Select(Csv)));
                    written++;
                }
                if (res.Items.Count < q.Limit) break;
                q.BeforeTicks = res.Items[^1].TimeUtc.Ticks;
                q.BeforeId = res.Items[^1].Id;
                StatusText.Text = $"Exporting… {written:N0}";
            }
            StatusText.Text = $"Exported {written:N0} entries to {dlg.FileName}";
        }
        catch (Exception ex) { ShowError("Export failed: " + ex.Message); }
        finally { Cursor = null; }
    }

    static string Csv(object? v)
    {
        var s = v?.ToString() ?? "";
        return s.IndexOfAny(new[] { ';', '"', '\n', '\r' }) >= 0 ? "\"" + s.Replace("\"", "\"\"") + "\"" : s;
    }

    void Min_Click(object sender, RoutedEventArgs e) => WindowState = WindowState.Minimized;
    void Max_Click(object sender, RoutedEventArgs e) => WindowState = WindowState == WindowState.Maximized ? WindowState.Normal : WindowState.Maximized;
    void Close_Click(object sender, RoutedEventArgs e) => Close();
}