using System.Reflection;
using System.Windows;
using DnsDefender.UI.Services;
using DnsDefender.UI.ViewModels;

namespace DnsDefender.UI;

public partial class MainWindow : Window
{
    private readonly SearchViewModel _viewModel;

    public MainWindow()
    {
        InitializeComponent();

        _viewModel = new SearchViewModel();
        DataContext = _viewModel;

        var infoVersion = Assembly.GetExecutingAssembly()
            .GetCustomAttribute<AssemblyInformationalVersionAttribute>()?
            .InformationalVersion ?? "未知版本";
        Title = $"DNS解析溯源工具 版本号：{infoVersion}  BY：wyc";

        var adminSuffix = AdminPrivilegeService.IsAdministrator()
            ? "当前为管理员权限。"
            : "当前非管理员权限，ETW 采集可能受限，将自动尝试降级日志模式。";

        MessageBox.Show(
            $"仅用于授权防御排查。请勿用于未授权目标。\n{adminSuffix}",
            "DNS解析请求进程定位工具",
            MessageBoxButton.OK,
            MessageBoxImage.Warning);
    }

    private void OnMainWindowLoaded(object sender, RoutedEventArgs e)
    {
        UpdateColumnVisibility();
    }

    private void OnColumnToggleChanged(object sender, RoutedEventArgs e)
    {
        UpdateColumnVisibility();
    }

    private void UpdateColumnVisibility()
    {
        ColQueryType.Visibility = ChkShowQueryType.IsChecked == true ? Visibility.Visible : Visibility.Collapsed;
        ColResponseCode.Visibility = ChkShowResponseCode.IsChecked == true ? Visibility.Visible : Visibility.Collapsed;
        ColReturnedIps.Visibility = ChkShowReturnedIps.IsChecked == true ? Visibility.Visible : Visibility.Collapsed;
        ColAttributionStatus.Visibility = ChkShowAttributionStatus.IsChecked == true ? Visibility.Visible : Visibility.Collapsed;
        ColAttributionConfidence.Visibility = ChkShowAttributionConfidence.IsChecked == true ? Visibility.Visible : Visibility.Collapsed;
    }

    protected override void OnClosed(EventArgs e)
    {
        _viewModel.Shutdown();
        base.OnClosed(e);
    }
}
