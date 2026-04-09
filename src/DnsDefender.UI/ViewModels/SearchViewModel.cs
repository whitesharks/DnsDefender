using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
using System.Runtime.CompilerServices;
using System.Windows;
using System.Windows.Input;
using System.Windows.Threading;
using Microsoft.Win32;
using DnsDefender.Common.Models;
using DnsDefender.Collector.Services;
using DnsDefender.Collector.Storage;
using DnsDefender.Collector.Pcap;
using DnsDefender.UI.Commands;
using DnsDefender.UI.Services;

namespace DnsDefender.UI.ViewModels;

public sealed class SearchViewModel : INotifyPropertyChanged
{
    private readonly TelemetryRepository _repository;
    private readonly DnsCollectorService _collectorService;
    private readonly ExportService _exportService;

    private string _domainKeyword = string.Empty;
    private DateTime _fromLocal = DateTime.Now.AddHours(-2);
    private DateTime _toLocal = DateTime.Now;
    private readonly DispatcherTimer _refreshTimer;

    private string _statusText = "就绪";
    private string _capabilityText = "能力探测：未检测";
    private bool _isCapturing;

    private bool _showQueryTypeColumn = true;
    private bool _showResponseCodeColumn = true;
    private bool _showReturnedIpsColumn = true;
    private bool _showAttributionStatusColumn = true;
    private bool _showAttributionConfidenceColumn = true;

    private bool _enablePacketCapture;
    private string _selectedCaptureInterfaceId = string.Empty;

    private readonly RelayCommand _startCaptureCommand;
    private readonly RelayCommand _stopCaptureCommand;
    private readonly RelayCommand _clearHistoryCommand;

    public SearchViewModel()
    {
        var dataRoot = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "DnsDefender");
        Directory.CreateDirectory(dataRoot);
        var dbPath = Path.Combine(dataRoot, "telemetry.db");

        _repository = new TelemetryRepository(dbPath);
        _collectorService = new DnsCollectorService(_repository);
        _exportService = new ExportService();

        Records = new ObservableCollection<DnsTelemetryRecord>();
        AvailableCaptureInterfaces = new ObservableCollection<PacketCaptureInterfaceInfo>();

        _refreshTimer = new DispatcherTimer
        {
            Interval = TimeSpan.FromSeconds(1.5)
        };
        _refreshTimer.Tick += (_, _) => Search();

        _startCaptureCommand = new RelayCommand(_ => StartCapture(), _ => !_isCapturing);
        _stopCaptureCommand = new RelayCommand(_ => StopCapture(), _ => _isCapturing);
        _clearHistoryCommand = new RelayCommand(_ => ClearHistory());

        StartCaptureCommand = _startCaptureCommand;
        StopCaptureCommand = _stopCaptureCommand;
        ClearHistoryCommand = _clearHistoryCommand;
        SearchCommand = new RelayCommand(_ => Search());
        ExportCsvCommand = new RelayCommand(_ => ExportCsv(), _ => Records.Count > 0);
        ExportJsonCommand = new RelayCommand(_ => ExportJson(), _ => Records.Count > 0);

        _repository.Initialize();
        LoadCaptureInterfaces();
        Search();
    }

    public event PropertyChangedEventHandler? PropertyChanged;

    public ObservableCollection<DnsTelemetryRecord> Records { get; }

    public ObservableCollection<PacketCaptureInterfaceInfo> AvailableCaptureInterfaces { get; }

    public ICommand StartCaptureCommand { get; }

    public ICommand StopCaptureCommand { get; }

    public ICommand SearchCommand { get; }

    public ICommand ClearHistoryCommand { get; }

    public ICommand ExportCsvCommand { get; }

    public ICommand ExportJsonCommand { get; }

    public string DomainKeyword
    {
        get => _domainKeyword;
        set
        {
            _domainKeyword = value;
            OnPropertyChanged();
        }
    }

    public DateTime FromLocal
    {
        get => _fromLocal;
        set
        {
            _fromLocal = value;
            OnPropertyChanged();
        }
    }

    public DateTime ToLocal
    {
        get => _toLocal;
        set
        {
            _toLocal = value;
            OnPropertyChanged();
        }
    }

    public string StatusText
    {
        get => _statusText;
        private set
        {
            _statusText = value;
            OnPropertyChanged();
        }
    }

    public bool ShowQueryTypeColumn
    {
        get => _showQueryTypeColumn;
        set
        {
            _showQueryTypeColumn = value;
            OnPropertyChanged();
        }
    }

    public bool ShowResponseCodeColumn
    {
        get => _showResponseCodeColumn;
        set
        {
            _showResponseCodeColumn = value;
            OnPropertyChanged();
        }
    }

    public bool ShowReturnedIpsColumn
    {
        get => _showReturnedIpsColumn;
        set
        {
            _showReturnedIpsColumn = value;
            OnPropertyChanged();
        }
    }

    public bool ShowAttributionStatusColumn
    {
        get => _showAttributionStatusColumn;
        set
        {
            _showAttributionStatusColumn = value;
            OnPropertyChanged();
        }
    }

    public bool ShowAttributionConfidenceColumn
    {
        get => _showAttributionConfidenceColumn;
        set
        {
            _showAttributionConfidenceColumn = value;
            OnPropertyChanged();
        }
    }

    public string CapabilityText
    {
        get => _capabilityText;
        private set
        {
            _capabilityText = value;
            OnPropertyChanged();
        }
    }

    public bool EnablePacketCapture
    {
        get => _enablePacketCapture;
        set
        {
            _enablePacketCapture = value;
            OnPropertyChanged();
            OnPropertyChanged(nameof(IsCaptureInterfaceSelectionEnabled));
        }
    }

    public string SelectedCaptureInterfaceId
    {
        get => _selectedCaptureInterfaceId;
        set
        {
            _selectedCaptureInterfaceId = value;
            OnPropertyChanged();
        }
    }

    public bool IsCaptureInterfaceSelectionEnabled => EnablePacketCapture && !_isCapturing;

    public void Shutdown()
    {
        _refreshTimer.Stop();
        _collectorService.Stop();
        _collectorService.Dispose();
    }

    private void StartCapture()
    {
        try
        {
            if (_isCapturing)
            {
                StatusText = "当前已在记录中";
                return;
            }

            UpdateCaptureCommandState();

            var startOptions = new CaptureStartOptions
            {
                EnablePacketCapture = EnablePacketCapture,
                PacketCaptureInterfaceId = SelectedCaptureInterfaceId
            };

            if (EnablePacketCapture && string.IsNullOrWhiteSpace(SelectedCaptureInterfaceId))
            {
                StatusText = "已启用抓包，但尚未选择网卡。";
                UpdateCaptureCommandState();
                return;
            }

            var startResult = _collectorService.StartWithFallback(startOptions);
            CapabilityText = $"能力探测：{startResult.CapabilityMessage}";

            if (!startResult.Started)
            {
                StatusText = startResult.Message;
                UpdateCaptureCommandState();
                return;
            }

            _isCapturing = true;
            UpdateCaptureCommandState();
            OnPropertyChanged(nameof(IsCaptureInterfaceSelectionEnabled));
            _refreshTimer.Start();

            if (startResult.Mode.Contains("ETW", StringComparison.OrdinalIgnoreCase))
            {
                var runtime = _collectorService.GetRuntimeEtwCapability();
                CapabilityText = $"能力探测：{runtime.Message}";
            }

            StatusText = startResult.Mode switch
            {
                "ETW+NameResolution+DNS-Operational+PCAP" => "正在记录 DNS 请求（ETW + NameResolution + 日志 + 抓包四通道）",
                "ETW+NameResolution+DNS-Operational" => "正在记录 DNS 请求（ETW + NameResolution + 日志三通道）",
                "ETW+NameResolution" => "正在记录 DNS 请求（ETW + NameResolution 双通道）",
                "ETW+NameResolution+PCAP" => "正在记录 DNS 请求（ETW + NameResolution + 抓包三通道）",
                "ETW+DNS-Operational+PCAP" => "正在记录 DNS 请求（ETW + 日志 + 抓包三通道）",
                "ETW+PCAP" => "正在记录 DNS 请求（ETW + 抓包双通道）",
                "ETW+DNS-Operational" => "正在记录 DNS 请求（ETW + 日志双通道）",
                "ETW+NameResolution+Operational" => "正在记录 DNS 请求（ETW + NameResolution + 日志三通道）",
                "DNS-Operational+PCAP" => "正在记录 DNS 请求（日志 + 抓包双通道）",
                "DNS-Operational" => "正在记录 DNS 请求（降级日志模式）",
                "PCAP" => "正在记录 DNS 请求（抓包模式）",
                "ETW" => "正在记录 DNS 请求（ETW 模式）",
                _ => "正在记录 DNS 请求（降级日志模式）"
            };
            Search();
        }
        catch (Exception ex)
        {
            StatusText = $"开始记录失败：{ex.Message}";
        }
    }

    private void StopCapture()
    {
        _refreshTimer.Stop();
        _collectorService.Stop();
        _isCapturing = false;
        UpdateCaptureCommandState();
        OnPropertyChanged(nameof(IsCaptureInterfaceSelectionEnabled));
        Search(suppressStatusUpdate: true);
        CapabilityText = "能力探测：已停止采集";
        StatusText = "已停止记录";
    }

    private void ClearHistory()
    {
        _repository.ClearAll();
        Records.Clear();
        RaiseExportCanExecute();
        StatusText = "历史日志已清理";
    }

    private void Search(bool suppressStatusUpdate = false)
    {
        var fromLocal = FromLocal.Date;
        var toLocal = ToLocal.Date.AddDays(1).AddTicks(-1);

        if (toLocal < fromLocal)
        {
            toLocal = fromLocal.AddDays(1).AddTicks(-1);
        }

        var fromUtc = DateTime.SpecifyKind(fromLocal, DateTimeKind.Local).ToUniversalTime();
        var toUtc = DateTime.SpecifyKind(toLocal, DateTimeKind.Local).ToUniversalTime();

        var records = _repository.Search(DomainKeyword, fromUtc, toUtc, 5000);

        Records.Clear();
        foreach (var item in records)
        {
            Records.Add(item);
        }

        if (!_isCapturing && !suppressStatusUpdate)
        {
            StatusText = $"已加载 {Records.Count} 条记录";
        }
        RaiseExportCanExecute();
    }

    private void ExportCsv()
    {
        var dialog = new SaveFileDialog
        {
            Filter = "CSV 文件 (*.csv)|*.csv",
            FileName = $"dns_records_{DateTime.Now:yyyyMMdd_HHmmss}.csv"
        };

        if (dialog.ShowDialog() != true)
        {
            return;
        }

        _exportService.ExportCsv(dialog.FileName, Records);
        MessageBox.Show("CSV 导出完成。", "DNS解析请求进程定位工具", MessageBoxButton.OK, MessageBoxImage.Information);
    }

    private void ExportJson()
    {
        var dialog = new SaveFileDialog
        {
            Filter = "JSON 文件 (*.json)|*.json",
            FileName = $"dns_records_{DateTime.Now:yyyyMMdd_HHmmss}.json"
        };

        if (dialog.ShowDialog() != true)
        {
            return;
        }

        _exportService.ExportJson(dialog.FileName, Records);
        MessageBox.Show("JSON 导出完成。", "DNS解析请求进程定位工具", MessageBoxButton.OK, MessageBoxImage.Information);
    }

    private void RaiseExportCanExecute()
    {
        if (ExportCsvCommand is RelayCommand csv)
        {
            csv.RaiseCanExecuteChanged();
        }

        if (ExportJsonCommand is RelayCommand json)
        {
            json.RaiseCanExecuteChanged();
        }
    }

    private void UpdateCaptureCommandState()
    {
        _startCaptureCommand.RaiseCanExecuteChanged();
        _stopCaptureCommand.RaiseCanExecuteChanged();
        OnPropertyChanged(nameof(IsCaptureInterfaceSelectionEnabled));
    }

    private void LoadCaptureInterfaces()
    {
        AvailableCaptureInterfaces.Clear();
        foreach (var nic in _collectorService.GetPacketCaptureInterfaces())
        {
            AvailableCaptureInterfaces.Add(nic);
        }

        if (AvailableCaptureInterfaces.Count > 0)
        {
            SelectedCaptureInterfaceId = AvailableCaptureInterfaces[0].InterfaceId;
        }
    }

    private void OnPropertyChanged([CallerMemberName] string? propertyName = null)
    {
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
    }
}
