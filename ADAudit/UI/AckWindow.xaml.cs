using System.Windows;
using System.Windows.Controls;
using ADAudit.Shared;

namespace ADAudit.UI;

public partial class AckWindow : Window
{
    readonly GuardItem _item;
    readonly IAuditSource _src;

    public AckWindow(GuardItem item, IAuditSource src)
    {
        _item = item;
        _src = src;
        InitializeComponent();
        SourceInitialized += (_, _) => Glass.Apply(this);
        Info.Text = $"{Dn.FriendlyName(item.MemberDn)} was added to {item.GroupName} by {item.AddedBy} " +
                    $"on {item.AddedUtc.ToLocalTime():yyyy-MM-dd HH:mm}." +
                    (item.Status == GuardStatus.Pending ? "\nAcknowledging also cancels the scheduled automatic removal." : "");
        Loaded += (_, _) => Reason.Focus();
    }

    void Reason_TextChanged(object sender, TextChangedEventArgs e) => OkBtn.IsEnabled = Reason.Text.Trim().Length >= 3;

    void Cancel_Click(object sender, RoutedEventArgs e) => DialogResult = false;

    async void Ok_Click(object sender, RoutedEventArgs e)
    {
        OkBtn.IsEnabled = false;
        try
        {
            await _src.AcknowledgeAsync(_item.Id, Reason.Text.Trim());
            DialogResult = true;
        }
        catch (Exception ex)
        {
            Msg.Text = ex.Message;
            Msg.Visibility = Visibility.Visible;
            OkBtn.IsEnabled = true;
        }
    }
}
