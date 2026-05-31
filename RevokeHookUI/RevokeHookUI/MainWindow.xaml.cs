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
    private readonly string _configPath;
    private readonly string? _installedVersion;
    private string? _currentWechatVersion;
    private RevokeHookConfig _currentConfig = new();

    public MainWindow()
    {
        InitializeComponent();

        _iniPath = Path.Combine(_baseDirectory, "RevokeHook.ini");
        _configPath = Path.Combine(_baseDirectory, "Config3.json");
        _installedVersion = WindowsSystemService.TryGetWeChatVersion();
        _currentWechatVersion = _installedVersion;

        Loaded += MainWindow_Loaded;
    }

    private void MainWindow_Loaded(object sender, RoutedEventArgs e)
    {
        EnsureLocalFiles();

        AppendLog("程序启动 v5.0.0。");
        AppendLog("INI 路径: " + _iniPath);
        AppendLog("Config3 路径: " + _configPath);

        if (!string.IsNullOrWhiteSpace(_installedVersion))
        {
            VersionHintTextBlock.Text = "已检测到微信版本: " + _installedVersion;
            AppendLog("当前微信版本: " + _installedVersion);
        }
        else
        {
            VersionHintTextBlock.Text = "未自动检测到微信版本, 将回退到 Config3.json 中最新版本。";
            AppendLog("未检测到微信版本, 将回退到 Config3.json 中最新版本。");
        }

        LoadIniConfiguration();
        LoadLocalConfigConfiguration();
    }

    private async void LoadCloudButton_Click(object sender, RoutedEventArgs e)
    {
        var progressWindow = new ProgressWindow("云端配置");
        progressWindow.Owner = this;
        progressWindow.Show();

        ToggleTopButtons(false);
        AppendLog("开始从 云端 下载 Config3.json。");

        try
        {
            var progress = new Progress<CloudDownloadProgress>(progressWindow.Report);
            await CloudConfigService.DownloadLatestConfigAsync(_configPath, progress);

            progressWindow.Report(new CloudDownloadProgress("云端配置下载完成, 正在解析...", 100, false));
            ApplyConfig(Config3Service.Load(_configPath));
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
            _currentConfig = config;
            WindowsSystemService.SetAutoRun("RevokeHook", config.Setting.AutoRun, Path.Combine(_baseDirectory, "RevokeInject.exe"));
            AppendLog("已保存微信版本(Ver): " + (string.IsNullOrWhiteSpace(config.Setting.Ver) ? "(空)" : config.Setting.Ver));
            AppendLog("配置已保存到 RevokeHook.ini。");
        }
        catch (Exception ex)
        {
            AppendLog("保存配置失败: " + ex.Message);
        }
    }

    private async void SearchAllButton_Click(object sender, RoutedEventArgs e)
    {
        await SearchCallChainsAsync();
    }

    private async Task SearchCallChainsAsync()
    {
        try
        {
            var wechatDllPath = ResolveWeChatDllPath();
            if (string.IsNullOrWhiteSpace(wechatDllPath))
            {
                AppendLog("已取消搜索。");
                return;
            }

            DeleteMessagesChainTextBox.Text = string.Empty;
            AddMessageToDbChainTextBox.Text = string.Empty;
            KeyFuncDelMsgOffsetTextBox.Text = string.Empty;
            KeyFuncAdd2DBOffsetTextBox.Text = string.Empty;
            UpdateSearchProgress(new CallChainSearchProgress(0, "准备搜索..."));

            ToggleTopButtons(false);
            AppendLog("开始搜索字符串引用与调用链: " + wechatDllPath);

            var request = new CallChainSearchRequest(
                Signature1TextBox.Text,
                Signature2TextBox.Text,
                Signature3TextBox.Text);
            var progress = new Progress<CallChainSearchProgress>(UpdateSearchProgress);

            var result = await Task.Run(() => CallChainSearchService.Search(wechatDllPath, request, progress));
            ApplySearchResult(result);
        }
        catch (Exception ex)
        {
            AppendLog("搜索失败: " + ex.Message);
            UpdateSearchProgress(new CallChainSearchProgress(0, "搜索失败"));
        }
        finally
        {
            ToggleTopButtons(true);
        }
    }

    private void ApplySearchResult(CallChainSearchResult result)
    {
        foreach (var candidateCount in result.CandidateCounts)
        {
            AppendLog($"{candidateCount.Key} 候选函数数量: {candidateCount.Value}" + (candidateCount.Value != 1 ? ", 注意候选函数数量不唯一" : ""));
        }

        AppendLocatedFunction(result.OriginFunction);
        AppendLocatedFunction(result.DeleteMessagesFunction);
        AppendLocatedFunction(result.AddMessageToDbFunction);

        if (!result.UsedNativeCapstone)
        {
            AppendLog("未加载到原生 capstone.dll, 已使用内置 lea/call 解析降级输出。");
        }

        if (result.DeleteMessagesChain is not null)
        {
            KeyFuncDelMsgOffsetTextBox.Text = NumericParser.FormatHexUnchecked(result.DeleteMessagesChain.RootCallRva);
            DeleteMessagesChainTextBox.Text = result.DeleteMessagesChain.Format();
            AppendLog("DeleteMessages 调用链已搜索完毕");
            // AppendLog(result.DeleteMessagesChain.Format());
        }
        else
        {
            AppendLog("未在三层调用深度内找到 DeleteMessages 调用链。");
        }

        if (result.AddMessageToDbChain is not null)
        {
            KeyFuncAdd2DBOffsetTextBox.Text = NumericParser.FormatHexUnchecked(result.AddMessageToDbChain.TargetCallRva);
            AddMessageToDbChainTextBox.Text = result.AddMessageToDbChain.Format();
            AppendLog("CoAddMessageToDB 调用链已搜索完毕");
            // AppendLog(result.AddMessageToDbChain.Format());
        }
        else
        {
            AppendLog("未在三层调用深度内找到 CoAddMessageToDB 调用链。");
        }

        AppendLog("搜索完成, 结果已回填到偏移框。");
    }

    private void AppendLocatedFunction(LocatedFunction function)
    {
        AppendLog(
            $"{function.Name}: stringFile={NumericParser.FormatHexUnchecked(function.StringFileOffset)}, stringRVA={NumericParser.FormatHexUnchecked(function.StringRva)}, leaFile={NumericParser.FormatHexUnchecked(function.LeaFileOffset)}, leaRVA={NumericParser.FormatHexUnchecked(function.LeaRva)}, funcRVA={NumericParser.FormatHexUnchecked(function.FunctionRva)}, insn={function.LeaInstructionText}");
    }

    private void UpdateSearchProgress(CallChainSearchProgress progress)
    {
        SearchProgressBar.Value = Math.Clamp(progress.Percent, 0, 100);
        SearchProgressTextBlock.Text = progress.Message;
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
            _currentConfig = config;
            LoadConfigToUi(config);
            AppendLog("已从 ini 加载本地配置。");
        }
        catch (Exception ex)
        {
            AppendLog("读取 ini 失败: " + ex.Message);
        }
    }

    private void LoadLocalConfigConfiguration()
    {
        if (!File.Exists(_configPath))
        {
            AppendLog("未找到 Config3.json, 特征码区域保持当前内容。");
            return;
        }

        try
        {
            ApplyConfig(Config3Service.Load(_configPath));
            AppendLog("已从 Config3.json 读取特征码信息。");
        }
        catch (Exception ex)
        {
            AppendLog("解析 Config3.json 失败: " + ex.Message);
        }
    }

    private void ApplyConfig(Config3File config3)
    {
        var lookupVersion = _currentWechatVersion ?? _installedVersion;

        if (Config3Service.TryGet(config3, lookupVersion, out var configVersion, out var entry))
        {
            Signature1TextBox.Text = entry.Sig1 ?? string.Empty;
            Signature2TextBox.Text = entry.Sig2 ?? string.Empty;
            Signature3TextBox.Text = entry.Sig3 ?? string.Empty;

            AppendLog("已选择版本特征: " + configVersion);
        }
        else
        {
            AppendLog("Config3.json 中没有可用的特征码数据。");
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

        AutoRunCheckBox.IsChecked = config.Setting.AutoRun;
        OutputDebugMsgCheckBox.IsChecked = config.Setting.OutputDebugMsg;
        OverTipCheckBox.IsChecked = config.Setting.OverTip;
        AntiRevokeSelfCheckBox.IsChecked = config.Setting.AntiRevokeSelf;
    }

    private RevokeHookConfig ReadConfigFromUi()
    {
        _currentConfig.KeyFunc = new KeyFuncSection
        {
            DelMsgOffset = NumericParser.ParseInt(KeyFuncDelMsgOffsetTextBox.Text),
            Add2DBOffset = NumericParser.ParseInt(KeyFuncAdd2DBOffsetTextBox.Text)
        };
        _currentConfig.Setting = new SettingSection
        {
            AutoRun = AutoRunCheckBox.IsChecked == true,
            OutputDebugMsg = OutputDebugMsgCheckBox.IsChecked == true,
            OverTip = OverTipCheckBox.IsChecked == true,
            AntiRevokeSelf = AntiRevokeSelfCheckBox.IsChecked == true,
            Ver = _currentWechatVersion ?? string.Empty
        };

        return _currentConfig;
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
