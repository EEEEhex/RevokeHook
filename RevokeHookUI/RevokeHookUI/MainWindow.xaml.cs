using System;
using System.IO;
using System.Threading.Tasks;
using System.Windows;
using Microsoft.Win32;
using RevokeHookUI.Models;
using RevokeHookUI.Services;

namespace RevokeHookUI;

public partial class MainWindow
{
    private readonly string _baseDirectory = AppContext.BaseDirectory;
    private readonly string _iniPath;
    private readonly string _config2Path;
    private readonly string? _installedVersion;
    private string? _displayedConfigTip;
    private string? _currentWechatVersion;

    public MainWindow()
    {
        InitializeComponent();

        _iniPath = Path.Combine(_baseDirectory, "RevokeHook.ini");
        _config2Path = Path.Combine(_baseDirectory, "Config2.json");
        _installedVersion = WindowsSystemService.TryGetWeChatVersion();
        _currentWechatVersion = _installedVersion;

        Loaded += MainWindow_Loaded;
    }

    private void MainWindow_Loaded(object sender, RoutedEventArgs e)
    {
        EnsureLocalFiles();

        AppendLog("程序启动 v4.1.1。");
        AppendLog("INI 路径: " + _iniPath);
        AppendLog("Config2 路径: " + _config2Path);

        if (!string.IsNullOrWhiteSpace(_installedVersion))
        {
            VersionHintTextBlock.Text = "已检测到微信版本: " + _installedVersion;
            AppendLog("当前微信版本: " + _installedVersion);
        }
        else
        {
            VersionHintTextBlock.Text = "未自动检测到微信版本, 将回退到 Config2.json 中最新版本。";
            AppendLog("未检测到微信版本, 将回退到 Config2.json 中最新版本。");
        }

        LoadIniConfiguration();
        LoadLocalConfig2Configuration();
    }

    private async void LoadCloudButton_Click(object sender, RoutedEventArgs e)
    {
        var progressWindow = new ProgressWindow("云端配置");
        progressWindow.Owner = this;
        progressWindow.Show();

        ToggleTopButtons(false);
        AppendLog("开始从 云端 下载 Config2.json。");

        try
        {
            var progress = new Progress<CloudDownloadProgress>(progressWindow.Report);
            await CloudConfigService.DownloadLatestConfigAsync(_config2Path, progress);

            progressWindow.Report(new CloudDownloadProgress("云端配置下载完成, 正在解析...", 100, false));
            ApplyConfig2(Config2Service.Load(_config2Path), applySpecificToUi: true, requireExactSpecificVersion: true);
            AppendLog("云端配置解析完成!");
            await progressWindow.DelayCloseAsync(700);
        }
        catch (Exception ex)
        {
            AppendLog("下载云端配置失败: " + ex.Message);
            progressWindow.Report(new CloudDownloadProgress("下载失败: " + ex.Message, null, false));
            await progressWindow.DelayCloseAsync(1800);
        }
        finally
        {
            ToggleTopButtons(true);
        }
    }

    private void SaveIniButton_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            var config = ReadConfigFromUi();
            IniService.Save(_iniPath, config);
            WindowsSystemService.SetAutoRun("RevokeHook", config.Setting.AutoRun, Path.Combine(_baseDirectory, "RevokeInject.exe"));
            AppendLog("已保存微信版本(Ver): " + (string.IsNullOrWhiteSpace(config.Setting.Ver) ? "(空)" : config.Setting.Ver));
            AppendLog("配置已保存到 RevokeHook.ini。");
        }
        catch (Exception ex)
        {
            AppendLog("保存配置失败: " + ex.Message);
        }
    }

    private async void SearchDelMsgButton_Click(object sender, RoutedEventArgs e)
    {
        await SearchSignatureAsync(
            "DelMsg",
            DelMsgPatternTextBox.Text,
            DelMsgResultDeltaTextBox.Text,
            DelMsgSearchResultTextBox,
            KeyFuncDelMsgOffsetTextBox);
    }

    private async void SearchAdd2DBButton_Click(object sender, RoutedEventArgs e)
    {
        await SearchSignatureAsync(
            "Add2DB",
            Add2DBPatternTextBox.Text,
            Add2DBResultDeltaTextBox.Text,
            Add2DBSearchResultTextBox,
            KeyFuncAdd2DBOffsetTextBox);
    }

    private async void SearchAllButton_Click(object sender, RoutedEventArgs e)
    {
        await SearchSignatureAsync(
            "DelMsg",
            DelMsgPatternTextBox.Text,
            DelMsgResultDeltaTextBox.Text,
            DelMsgSearchResultTextBox,
            KeyFuncDelMsgOffsetTextBox);

        await SearchSignatureAsync(
            "Add2DB",
            Add2DBPatternTextBox.Text,
            Add2DBResultDeltaTextBox.Text,
            Add2DBSearchResultTextBox,
            KeyFuncAdd2DBOffsetTextBox);
    }

    private void CreateLinkButton_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            var shortcutPath = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory),
                "微信Revoke.lnk");
            var targetPath = Path.Combine(_baseDirectory, "RevokeInject.exe");

            WindowsSystemService.CreateShortcut(shortcutPath, targetPath, _baseDirectory);
            AppendLog("桌面快捷方式创建成功: " + shortcutPath);
        }
        catch (Exception ex)
        {
            AppendLog("创建桌面快捷方式失败: " + ex.Message);
        }
    }

    private async void CheckUpdateButton_Click(object sender, RoutedEventArgs e)
    {
        CheckUpdateButton.IsEnabled = false;
        AppendLog("开始检查 GitHub Releases 更新...");

        try
        {
            var result = await UpdateCheckService.CheckForUpdatesAsync();
            if (result.HasUpdate)
            {
                var message =
                    $"发现新版本。\n当前版本: {result.CurrentVersion}\n最新版本: {result.LatestVersion}\n发布页: {result.ReleaseUrl}";
                AppendLog($"检测到新版本: {result.LatestVersion}");
                MessageBox.Show(this, message, "检查更新", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }

            var latestMessage =
                $"当前已是最新版本。\n当前版本: {result.CurrentVersion}\n最新版本: {result.LatestVersion}";
            AppendLog("当前已是最新版本。");
            MessageBox.Show(this, latestMessage, "检查更新", MessageBoxButton.OK, MessageBoxImage.Information);
        }
        catch (Exception ex)
        {
            AppendLog("检查更新失败: " + ex.Message);
            MessageBox.Show(this, "检查更新失败: " + ex.Message, "检查更新", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
        finally
        {
            CheckUpdateButton.IsEnabled = true;
        }
    }

    private void ClearLogButton_Click(object sender, RoutedEventArgs e)
    {
        var result = MessageBox.Show(
            this,
            "是否同时清空本地日志?",
            "清空日志",
            MessageBoxButton.YesNo,
            MessageBoxImage.Question);

        LogTextBox.Clear();

        if (result != MessageBoxResult.Yes)
        {
            AppendLog("日志文本框已清空。");
            return;
        }

        var deletedCount = ClearLocalLogFiles();
        if (deletedCount >= 0)
        {
            AppendLog($"日志文本框已清空, 本地 logs 文件已删除 {deletedCount} 个。");
            return;
        }

        AppendLog("日志文本框已清空, 但本地 logs 文件清理失败。");
    }

    private void EnsureLocalFiles()
    {
        if (!File.Exists(_iniPath))
        {
            IniService.Save(_iniPath, new RevokeHookConfig());
        }
    }

    private void LoadIniConfiguration()
    {
        try
        {
            var config = IniService.Load(_iniPath);
            LoadConfigToUi(config);
            AppendLog("已从 ini 加载本地配置。");
        }
        catch (Exception ex)
        {
            AppendLog("读取 ini 失败: " + ex.Message);
        }
    }

    private void LoadLocalConfig2Configuration()
    {
        if (!File.Exists(_config2Path))
        {
            AppendLog("未找到 Config2.json, 特征码区域保持当前内容。");
            return;
        }

        try
        {
            ApplyConfig2(Config2Service.Load(_config2Path), applySpecificToUi: false, showStartupTip: true);
            AppendLog("已从 Config2.json 读取特征码信息。");
        }
        catch (Exception ex)
        {
            AppendLog("解析 Config2.json 失败: " + ex.Message);
        }
    }

    private void ApplyConfig2(
        Config2File config2,
        bool applySpecificToUi,
        bool showStartupTip = false,
        bool requireExactSpecificVersion = false)
    {
        var lookupVersion = _currentWechatVersion ?? _installedVersion;

        if (Config2Service.TryGetGeneral(config2, lookupVersion, out var generalVersion, out var generalEntry))
        {
            DelMsgPatternTextBox.Text = generalEntry.Sig1 ?? string.Empty;
            Add2DBPatternTextBox.Text = generalEntry.Sig2 ?? string.Empty;
            DelMsgResultDeltaTextBox.Text = generalEntry.Sig1Delta ?? "0x0";
            Add2DBResultDeltaTextBox.Text = generalEntry.Sig2Delta ?? "0x0";

            AppendLog("已选择 通用 版本特征: " + generalVersion);
            ShowGeneralTipIfNeeded(generalEntry, generalVersion, showStartupTip);

            if (applySpecificToUi)
            {
                ApplyGeneralArgsToUi(generalEntry);
            }
        }
        else
        {
            AppendLog("Config2.json 中没有可用的 通用 数据。");
        }

        if (!applySpecificToUi)
        {
            return;
        }

        if (requireExactSpecificVersion && !string.IsNullOrWhiteSpace(lookupVersion))
        {
            if (!Config2Service.TryGetExactSpecific(config2, lookupVersion, out _, out _))
            {
                const string tipMessage = "云端配置中不存在与本地版本相等的配置, 请使用'搜索全部'";
                AppendLog(tipMessage);
                MessageBox.Show(this, tipMessage, "云端配置", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }
        }

        if (Config2Service.TryGetSpecific(config2, lookupVersion, out var specificVersion, out var specificEntry))
        {
            AppendLog("已选择 特定 版本特征: " + specificVersion);
            ApplySpecificConfigToUi(specificEntry);

            if (specificEntry.DelMsg is null)
            {
                AppendLog("特定版本缺少 DelMsg 字段, 已回退使用通用参数。");
            }

            if (specificEntry.Add2DB is null)
            {
                AppendLog("特定版本缺少 Add2DB 字段, 已回退使用通用参数。");
            }

            return;
        }

        AppendLog("云端配置没有命中 特定 版本, 已仅回填 通用 搜索参数。");
    }

    private void ShowGeneralTipIfNeeded(Config2GeneralEntry generalEntry, string version, bool showStartupTip)
    {
        if (string.IsNullOrWhiteSpace(generalEntry.Tips))
        {
            return;
        }

        var tip = generalEntry.Tips.Trim();
        if (string.Equals(_displayedConfigTip, tip, StringComparison.Ordinal))
        {
            return;
        }

        _displayedConfigTip = tip;
        AppendLog("========== 提示 ==========");
        AppendLog($"[Config2 {version}] {tip}");
        AppendLog("==============================");

        if (!showStartupTip)
        {
            return;
        }

        if (tip.StartsWith("[!]")) {
            MessageBox.Show(
                this,
                tip,
                $"Config2 重要提示 - {version}",
                MessageBoxButton.OK,
                MessageBoxImage.Information);
        }
    }

    private void ApplyGeneralArgsToUi(Config2GeneralEntry generalEntry)
    {
        DelMsgArgMsgIndexTextBox.Text = generalEntry.Sig1ArgMsgIndex ?? DelMsgArgMsgIndexTextBox.Text;
        DelMsgOffsetRevokeXmlTextBox.Text = generalEntry.Sig1OffsetRevokeXml ?? DelMsgOffsetRevokeXmlTextBox.Text;

        Add2DBArgMsgIndexTextBox.Text = generalEntry.Sig2ArgMsgIndex ?? Add2DBArgMsgIndexTextBox.Text;
        Add2DBArgBoolIndexTextBox.Text = generalEntry.Sig2ArgBoolIndex ?? Add2DBArgBoolIndexTextBox.Text;
        Add2DBOffsetRevokeXmlTextBox.Text = generalEntry.Sig2OffsetRevokeXml ?? Add2DBOffsetRevokeXmlTextBox.Text;
        Add2DBOffsetSrvIdTextBox.Text = generalEntry.Sig2OffsetSrvId ?? Add2DBOffsetSrvIdTextBox.Text;
    }

    private void ApplySpecificConfigToUi(Config2SpecificEntry specificEntry)
    {
        if (specificEntry.KeyFunc is not null)
        {
            KeyFuncDelMsgOffsetTextBox.Text = specificEntry.KeyFunc.DelMsgOffset ?? KeyFuncDelMsgOffsetTextBox.Text;
            KeyFuncAdd2DBOffsetTextBox.Text = specificEntry.KeyFunc.Add2DBOffset ?? KeyFuncAdd2DBOffsetTextBox.Text;
        }

        if (specificEntry.DelMsg is not null)
        {
            DelMsgArgMsgIndexTextBox.Text = specificEntry.DelMsg.ArgMsgIndex ?? DelMsgArgMsgIndexTextBox.Text;
            DelMsgOffsetRevokeXmlTextBox.Text = specificEntry.DelMsg.OffsetRevokeXml ?? DelMsgOffsetRevokeXmlTextBox.Text;
        }

        if (specificEntry.Add2DB is not null)
        {
            Add2DBArgMsgIndexTextBox.Text = specificEntry.Add2DB.ArgMsgIndex ?? Add2DBArgMsgIndexTextBox.Text;
            Add2DBArgBoolIndexTextBox.Text = specificEntry.Add2DB.ArgBoolIndex ?? Add2DBArgBoolIndexTextBox.Text;
            Add2DBOffsetRevokeXmlTextBox.Text = specificEntry.Add2DB.OffsetRevokeXml ?? Add2DBOffsetRevokeXmlTextBox.Text;
            Add2DBOffsetSrvIdTextBox.Text = specificEntry.Add2DB.OffsetSrvId ?? Add2DBOffsetSrvIdTextBox.Text;
        }
    }

    private async Task SearchSignatureAsync(
        string name,
        string patternText,
        string deltaText,
        System.Windows.Controls.TextBox resultTextBox,
        System.Windows.Controls.TextBox targetOffsetTextBox)
    {
        try
        {
            var wechatDllPath = ResolveWeChatDllPath();
            if (string.IsNullOrWhiteSpace(wechatDllPath))
            {
                AppendLog("已取消搜索 " + name + "。");
                return;
            }

            var delta = NumericParser.ParseInt(deltaText);
            AppendLog($"开始搜索 {name} 特征码, 结果偏移: {NumericParser.FormatHex(delta)}");

            var result = await Task.Run(() => SignatureSearchService.Search(wechatDllPath, patternText, delta));
            if (result.Matches.Count == 0)
            {
                resultTextBox.Text = string.Empty;
                AppendLog($"{name} 未找到匹配结果。");
                return;
            }

            for (var index = 0; index < result.Matches.Count; index++)
            {
                var match = result.Matches[index];
                AppendLog(
                    $"[{name}] 命中 {index}: RVA={NumericParser.FormatHex(match.BaseOffset)} 调整后={NumericParser.FormatHex(match.AdjustedOffset)} 预览={match.PreviewHex}");
            }

            var first = result.Matches[0];
            var formattedOffset = NumericParser.FormatHex(first.AdjustedOffset);
            resultTextBox.Text = first.PreviewHex;
            targetOffsetTextBox.Text = formattedOffset;
            AppendLog($"{name} 搜索完成, 已回填偏移: {formattedOffset}");
        }
        catch (Exception ex)
        {
            AppendLog($"搜索 {name} 失败: {ex.Message}");
        }
    }

    private string? ResolveWeChatDllPath()
    {
        var detectedPath = WindowsSystemService.TryGetWeChatDllPath();
        if (!string.IsNullOrWhiteSpace(detectedPath) && File.Exists(detectedPath))
        {
            _currentWechatVersion = _installedVersion ?? TryExtractWechatVersionFromDllPath(detectedPath);
            AppendLog("自动定位到 Weixin.dll: " + detectedPath);
            return detectedPath;
        }

        var dialog = new OpenFileDialog
        {
            CheckFileExists = true,
            Filter = "Weixin.dll|Weixin.dll|DLL 文件|*.dll",
            Title = "请选择 Weixin.dll"
        };

        if (dialog.ShowDialog(this) != true)
        {
            return null;
        }

        _currentWechatVersion = TryExtractWechatVersionFromDllPath(dialog.FileName) ?? _currentWechatVersion;
        if (!string.IsNullOrWhiteSpace(_currentWechatVersion))
        {
            VersionHintTextBlock.Text = "当前使用微信版本: " + _currentWechatVersion;
            AppendLog("已从手动选择路径识别微信版本: " + _currentWechatVersion);
        }

        return dialog.FileName;
    }

    private void ToggleTopButtons(bool isEnabled)
    {
        LoadCloudButton.IsEnabled = isEnabled;
        SaveIniButton.IsEnabled = isEnabled;
        SearchAllButton.IsEnabled = isEnabled;
        CreateLinkButton.IsEnabled = isEnabled;
        CheckUpdateButton.IsEnabled = isEnabled;
    }

    private void LoadConfigToUi(RevokeHookConfig config)
    {
        KeyFuncDelMsgOffsetTextBox.Text = NumericParser.FormatCompact(config.KeyFunc.DelMsgOffset);
        KeyFuncAdd2DBOffsetTextBox.Text = NumericParser.FormatCompact(config.KeyFunc.Add2DBOffset);

        DelMsgArgMsgIndexTextBox.Text = NumericParser.FormatCompact(config.DelMsg.ArgMsgIndex);
        DelMsgOffsetRevokeXmlTextBox.Text = NumericParser.FormatCompact(config.DelMsg.OffsetRevokeXML);

        Add2DBArgMsgIndexTextBox.Text = NumericParser.FormatCompact(config.Add2DB.ArgMsgIndex);
        Add2DBArgBoolIndexTextBox.Text = NumericParser.FormatCompact(config.Add2DB.ArgBoolIndex);
        Add2DBOffsetRevokeXmlTextBox.Text = NumericParser.FormatCompact(config.Add2DB.OffsetRevokeXML);
        Add2DBOffsetSrvIdTextBox.Text = NumericParser.FormatCompact(config.Add2DB.OffsetSrvID);

        AutoRunCheckBox.IsChecked = config.Setting.AutoRun;
        OutputDebugMsgCheckBox.IsChecked = config.Setting.OutputDebugMsg;
        OverTipCheckBox.IsChecked = config.Setting.OverTip;
        AntiRevokeSelfCheckBox.IsChecked = config.Setting.AntiRevokeSelf;
    }

    private RevokeHookConfig ReadConfigFromUi()
    {
        return new RevokeHookConfig
        {
            KeyFunc = new KeyFuncSection
            {
                DelMsgOffset = NumericParser.ParseInt(KeyFuncDelMsgOffsetTextBox.Text),
                Add2DBOffset = NumericParser.ParseInt(KeyFuncAdd2DBOffsetTextBox.Text)
            },
            DelMsg = new DelMsgSection
            {
                ArgMsgIndex = NumericParser.ParseInt(DelMsgArgMsgIndexTextBox.Text),
                OffsetRevokeXML = NumericParser.ParseInt(DelMsgOffsetRevokeXmlTextBox.Text)
            },
            Add2DB = new Add2DbSection
            {
                ArgMsgIndex = NumericParser.ParseInt(Add2DBArgMsgIndexTextBox.Text),
                ArgBoolIndex = NumericParser.ParseInt(Add2DBArgBoolIndexTextBox.Text),
                OffsetRevokeXML = NumericParser.ParseInt(Add2DBOffsetRevokeXmlTextBox.Text),
                OffsetSrvID = NumericParser.ParseInt(Add2DBOffsetSrvIdTextBox.Text)
            },
            Setting = new SettingSection
            {
                AutoRun = AutoRunCheckBox.IsChecked == true,
                OutputDebugMsg = OutputDebugMsgCheckBox.IsChecked == true,
                OverTip = OverTipCheckBox.IsChecked == true,
                AntiRevokeSelf = AntiRevokeSelfCheckBox.IsChecked == true,
                Ver = _currentWechatVersion ?? string.Empty
            }
        };
    }

    private static string? TryExtractWechatVersionFromDllPath(string dllPath)
    {
        var directory = Path.GetDirectoryName(dllPath);
        if (string.IsNullOrWhiteSpace(directory))
        {
            return null;
        }

        var version = Path.GetFileName(directory);
        if (string.IsNullOrWhiteSpace(version) || !version.Contains('.'))
        {
            return null;
        }

        return version;
    }

    private int ClearLocalLogFiles()
    {
        try
        {
            var logsPath = Path.Combine(_baseDirectory, "logs");
            if (!Directory.Exists(logsPath))
            {
                return 0;
            }

            var deletedCount = 0;
            foreach (var filePath in Directory.EnumerateFiles(logsPath, "*", SearchOption.AllDirectories))
            {
                File.Delete(filePath);
                deletedCount++;
            }

            return deletedCount;
        }
        catch
        {
            return -1;
        }
    }

    private void AppendLog(string message)
    {
        LogTextBox.AppendText($"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] {message}{Environment.NewLine}");
        LogTextBox.ScrollToEnd();
    }
}
