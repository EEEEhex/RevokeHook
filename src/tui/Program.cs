using Terminal.Gui;
using RevokeHookTUI.Models;
using RevokeHookTUI.Services;

namespace RevokeHookTUI;

internal static class Program
{
    private static readonly string BaseDirectory = AppContext.BaseDirectory;
    private static readonly string IniPath = Path.Combine(BaseDirectory, "RevokeHook.ini");
    private static readonly string ConfigPath = Path.Combine(BaseDirectory, "Config3.json");

    private static TextField _binaryPathText = null!;
    private static ComboBox _versionComboBox = null!;
    private static TextField _signature1Text = null!;
    private static TextField _signature2Text = null!;
    private static TextField _signature3Text = null!;
    private static TextField _deleteOffsetText = null!;
    private static TextField _addDbOffsetText = null!;
    private static TextView _deleteChainText = null!;
    private static TextView _addDbChainText = null!;
    private static TextView _logText = null!;
    private static ProgressBar _progressBar = null!;
    private static Label _progressLabel = null!;
    private static CheckBox _autoRunCheck = null!;
    private static CheckBox _outputDebugCheck = null!;
    private static CheckBox _overTipCheck = null!;
    private static CheckBox _antiRevokeSelfCheck = null!;
    private static readonly List<Button> Buttons = new();
    private static Config3File? _currentConfig3;
    private static List<string> _configVersions = new();
    private static bool _updatingVersionCombo;

    private static RevokeHookConfig _currentConfig = new();

    public static void Main()
    {
        Directory.CreateDirectory(BaseDirectory);
        EnsureLocalFiles();

        Application.Init();
        try
        {
            BuildUi();
            LoadInitialConfiguration();
            Application.Run();
        }
        finally
        {
            Application.Shutdown();
        }
    }

    private static void BuildUi()
    {
        var top = Application.Top;
        var menu = new MenuBar(new[]
        {
            new MenuBarItem("_File", new[]
            {
                new MenuItem("_Save", string.Empty, SaveIni),
                new MenuItem("_Quit", string.Empty, () => Application.RequestStop())
            }),
            new MenuBarItem("_Tools", new[]
            {
                new MenuItem("_Download Config3", string.Empty, () => _ = DownloadConfigAsync()),
                new MenuItem("_Search", string.Empty, () => _ = SearchAsync()),
                new MenuItem("_Detect WeChat", string.Empty, () => _ = DetectFlatpakWeChatAsync(true)),
                new MenuItem("_Create Shortcut", string.Empty, () => _ = CreateDesktopShortcutAsync()),
                new MenuItem("_Check Update", string.Empty, () => _ = CheckUpdateAsync()),
                new MenuItem("_Clear Log", string.Empty, ClearLog)
            })
        });
        top.Add(menu);

        var win = new Window("RevokeHook Linux TUI")
        {
            X = 0,
            Y = 1,
            Width = Dim.Fill(),
            Height = Dim.Fill()
        };
        top.Add(win);

        var title = new Label("RevokeHook 配置工具")
        {
            X = 1,
            Y = 0,
            Width = 24
        };
        win.Add(title);

        var pathLabel = new Label("Linux 程序路径:")
        {
            X = 1,
            Y = 2
        };
        _binaryPathText = new TextField(string.Empty)
        {
            X = 16,
            Y = 2,
            Width = Dim.Fill(2)
        };
        win.Add(pathLabel, _binaryPathText);

        var versionLabel = new Label("特征码版本:")
        {
            X = 1,
            Y = 4
        };
        _versionComboBox = new ComboBox()
        {
            X = 16,
            Y = 4,
            Width = 28,
            Height = 8
        };
        _versionComboBox.SelectedItemChanged += _ =>
        {
            if (_updatingVersionCombo)
            {
                return;
            }

            ApplySelectedVersionFromCombo();
        };
        win.Add(versionLabel, _versionComboBox);

        _signature1Text = AddLabeledTextField(win, "特征码1:", 6);
        _signature2Text = AddLabeledTextField(win, "特征码2:", 8);
        _signature3Text = AddLabeledTextField(win, "特征码3:", 10);

        _deleteOffsetText = AddLabeledTextField(win, "DelMsg 偏移:", 12, 24);
        _addDbOffsetText = AddLabeledTextField(win, "Add2DB 偏移:", 14, 24);
        _deleteOffsetText.ReadOnly = true;
        _addDbOffsetText.ReadOnly = true;

        _autoRunCheck = new CheckBox(1, 16, "AutoRun");
        _outputDebugCheck = new CheckBox(18, 16, "OutputDebugMsg");
        _overTipCheck = new CheckBox(42, 16, "OverTip");
        _antiRevokeSelfCheck = new CheckBox(58, 16, "AntiRevokeSelf");
        win.Add(_autoRunCheck, _outputDebugCheck, _overTipCheck, _antiRevokeSelfCheck);

        AddButton(win, 1, 18, "云端配置", () => _ = DownloadConfigAsync());
        AddButton(win, 14, 18, "保存配置", SaveIni);
        AddButton(win, 27, 18, "开始搜索", () => _ = SearchAsync());
        AddButton(win, 40, 18, "检查更新", () => _ = CheckUpdateAsync());
        AddButton(win, 53, 18, "清空日志", ClearLog);
        AddButton(win, 66, 18, "创建快捷方式", () => _ = CreateDesktopShortcutAsync());

        _progressBar = new ProgressBar
        {
            X = 1,
            Y = 20,
            Width = Dim.Percent(60),
            Height = 1
        };
        _progressLabel = new Label("等待搜索")
        {
            X = Pos.Right(_progressBar) + 2,
            Y = 20,
            Width = Dim.Fill(1)
        };
        win.Add(_progressBar, _progressLabel);

        _deleteChainText = new TextView
        {
            X = 1,
            Y = 22,
            Width = Dim.Percent(50) - 1,
            Height = 8,
            ReadOnly = true,
            WordWrap = false
        };
        _addDbChainText = new TextView
        {
            X = Pos.Right(_deleteChainText) + 1,
            Y = 22,
            Width = Dim.Fill(1),
            Height = 8,
            ReadOnly = true,
            WordWrap = false
        };
        win.Add(_deleteChainText, _addDbChainText);

        _logText = new TextView
        {
            X = 1,
            Y = Pos.Bottom(_deleteChainText) + 1,
            Width = Dim.Fill(1),
            Height = Dim.Fill(1),
            ReadOnly = true,
            WordWrap = true
        };
        win.Add(_logText);
    }

    private static TextField AddLabeledTextField(Window win, string label, int y, int widthOffset = 2)
    {
        var labelView = new Label(label)
        {
            X = 1,
            Y = y
        };
        var field = new TextField(string.Empty)
        {
            X = 16,
            Y = y,
            Width = Dim.Fill(widthOffset)
        };
        win.Add(labelView, field);
        return field;
    }

    private static void AddButton(Window win, int x, int y, string text, Action action)
    {
        var button = new Button(x, y, text);
        button.Clicked += action;
        Buttons.Add(button);
        win.Add(button);
    }

    private static void LoadInitialConfiguration()
    {
        AppendLog("程序启动。");
        AppendLog("INI 路径: " + IniPath);
        AppendLog("Config3 路径: " + ConfigPath);
        LoadIniConfiguration();
        LoadLocalConfigConfiguration();
        _ = DetectFlatpakWeChatAsync(false);
    }

    private static void EnsureLocalFiles()
    {
        if (!File.Exists(IniPath))
        {
            IniService.Save(IniPath, new RevokeHookConfig());
        }
    }

    private static void LoadIniConfiguration()
    {
        try
        {
            var config = IniService.Load(IniPath);
            _currentConfig = config;
            LoadConfigToUi(config);
            AppendLog("已从 ini 加载本地配置。");
        }
        catch (Exception ex)
        {
            AppendLog("读取 ini 失败: " + ex.Message);
        }
    }

    private static void LoadLocalConfigConfiguration()
    {
        if (!File.Exists(ConfigPath))
        {
            AppendLog("未找到 Config3.json, 特征码区域保持当前内容。");
            return;
        }

        try
        {
            LoadConfig3ToVersionCombo(Config3Service.Load(ConfigPath));
            AppendLog("已从 Config3.json 读取特征码信息。");
        }
        catch (Exception ex)
        {
            AppendLog("解析 Config3.json 失败: " + ex.Message);
        }
    }

    private static async Task DownloadConfigAsync()
    {
        ToggleButtons(false);
        try
        {
            AppendLog("开始从云端下载 Config3.json。");
            var progress = new Progress<CloudDownloadProgress>(item =>
            {
                AppendLog(item.Message);
                if (item.Percentage is { } percentage)
                {
                    UpdateProgress((int)Math.Clamp(percentage, 0, 100), item.Message);
                }
            });

            await CloudConfigService.DownloadLatestConfigAsync(ConfigPath, progress);
            LoadConfig3ToVersionCombo(Config3Service.Load(ConfigPath));
            UpdateProgress(100, "云端配置下载完成");
            AppendLog("云端配置解析完成。");
        }
        catch (Exception ex)
        {
            AppendLog("下载云端配置失败: " + ex.Message);
            ShowError("云端配置", ex.Message);
        }
        finally
        {
            ToggleButtons(true);
        }
    }

    private static async Task SearchAsync()
    {
        var binaryPath = GetText(_binaryPathText);
        if (string.IsNullOrWhiteSpace(binaryPath) || !File.Exists(binaryPath))
        {
            ShowError("开始搜索", "请先填写存在的 Linux 程序路径。");
            return;
        }

        ToggleButtons(false);
        try
        {
            _deleteChainText.Text = string.Empty;
            _addDbChainText.Text = string.Empty;
            _deleteOffsetText.Text = string.Empty;
            _addDbOffsetText.Text = string.Empty;
            UpdateProgress(0, "准备搜索...");
            AppendLog("开始搜索字符串引用与调用链: " + binaryPath);

            var request = new CallChainSearchRequest(
                GetText(_signature1Text),
                GetText(_signature2Text),
                GetText(_signature3Text));
            var lastProgressMessage = string.Empty;
            var progress = new Progress<CallChainSearchProgress>(item =>
            {
                UpdateProgress(item.Percent, item.Message);
                if (!string.Equals(lastProgressMessage, item.Message, StringComparison.Ordinal))
                {
                    lastProgressMessage = item.Message;
                    AppendLog($"进度 {item.Percent}%: {item.Message}");
                }
            });

            var result = await Task.Run(() => CallChainSearchService.Search(binaryPath, request, progress));
            ApplySearchResult(result);
        }
        catch (Exception ex)
        {
            AppendLog("搜索失败: " + ex.Message);
            UpdateProgress(0, "搜索失败");
            ShowError("搜索失败", ex.Message);
        }
        finally
        {
            ToggleButtons(true);
        }
    }

    private static async Task CheckUpdateAsync()
    {
        ToggleButtons(false);
        try
        {
            AppendLog("开始检查 GitHub Releases 更新...");
            var result = await UpdateCheckService.CheckForUpdatesAsync();
            var message = result.HasUpdate
                ? $"发现新版本: {result.LatestVersion}\n当前版本: {result.CurrentVersion}\n发布页: {result.ReleaseUrl}"
                : $"当前已是最新版本。\n当前版本: {result.CurrentVersion}\n最新版本: {result.LatestVersion}";
            AppendLog(result.HasUpdate ? "检测到新版本: " + result.LatestVersion : "当前已是最新版本。");
            ShowMessage("检查更新", message);
        }
        catch (Exception ex)
        {
            AppendLog("检查更新失败: " + ex.Message);
            ShowError("检查更新", ex.Message);
        }
        finally
        {
            ToggleButtons(true);
        }
    }

    private static async Task DetectFlatpakWeChatAsync(bool showDialog)
    {
        try
        {
            var info = await FlatpakWeChatService.DetectAsync();
            if (!info.Installed)
            {
                AppendLog("未检测到 flatpak 微信 com.tencent.WeChat。");
                if (showDialog)
                {
                    ShowError("探测微信版本", "暂不支持");
                }

                return;
            }

            var version = string.IsNullOrWhiteSpace(info.Version) ? "未知" : info.Version;
            AppendLog("Flatpak 微信版本: " + version);
            if (!string.IsNullOrWhiteSpace(info.InstallLocation))
            {
                AppendLog("Flatpak 微信安装路径: " + info.InstallLocation);
            }

            if (!string.IsNullOrWhiteSpace(info.BinaryPath))
            {
                _binaryPathText.Text = info.BinaryPath;
                AppendLog("已自动填充 Linux 程序路径: " + info.BinaryPath);
            }

            if (showDialog)
            {
                var binaryPath = string.IsNullOrWhiteSpace(info.BinaryPath) ? "未知" : info.BinaryPath;
                ShowMessage("探测微信版本", $"Flatpak 微信版本: {version}\n二进制路径: {binaryPath}");
            }
        }
        catch (Exception ex)
        {
            AppendLog("探测 flatpak 微信失败: " + ex.Message);
            if (showDialog)
            {
                ShowError("探测微信版本", ex.Message);
            }
        }
    }

    private static async Task CreateDesktopShortcutAsync()
    {
        ToggleButtons(false);
        try
        {
            var result = await FlatpakWeChatService.CreateShortcutAsync(BaseDirectory);
            AppendLog("快捷方式已创建: " + result.DesktopFilePath);
            AppendLog("启动命令: " + result.ExecCommand);
            ShowMessage("创建快捷方式", "快捷方式已创建:\n" + result.DesktopFilePath);
        }
        catch (NotSupportedException ex) when (ex.Message == "暂不支持")
        {
            AppendLog("未检测到 flatpak 微信 com.tencent.WeChat, 暂不支持创建快捷方式。");
            ShowError("创建快捷方式", "暂不支持");
        }
        catch (Exception ex)
        {
            AppendLog("创建快捷方式失败: " + ex.Message);
            ShowError("创建快捷方式", ex.Message);
        }
        finally
        {
            ToggleButtons(true);
        }
    }

    private static void SaveIni()
    {
        try
        {
            var config = ReadConfigFromUi();
            IniService.Save(IniPath, config);
            _currentConfig = config;
            AppendLog("配置已保存到 RevokeHook.ini。");
        }
        catch (Exception ex)
        {
            AppendLog("保存配置失败: " + ex.Message);
            ShowError("保存配置", ex.Message);
        }
    }

    private static void ClearLog()
    {
        _logText.Text = string.Empty;
        AppendLog("日志已清空。");
    }

    private static void LoadConfig3ToVersionCombo(Config3File config3)
    {
        _currentConfig3 = config3;
        _configVersions = config3.Versions.Keys
            .OrderByDescending(VersionSortKey)
            .ToList();

        _updatingVersionCombo = true;
        try
        {
            _versionComboBox.SetSource(_configVersions);
            if (_configVersions.Count == 0)
            {
                _versionComboBox.Text = string.Empty;
                AppendLog("Config3.json 中没有可用的特征码数据。");
                return;
            }

            var selectedIndex = 0;
            if (!string.IsNullOrWhiteSpace(_currentConfig.Setting.Ver))
            {
                var matchedIndex = _configVersions.FindIndex(version =>
                    string.Equals(NormalizeVersion(version), NormalizeVersion(_currentConfig.Setting.Ver), StringComparison.Ordinal));
                if (matchedIndex >= 0)
                {
                    selectedIndex = matchedIndex;
                }
            }

            _versionComboBox.SelectedItem = selectedIndex;
            _versionComboBox.Text = _configVersions[selectedIndex];
        }
        finally
        {
            _updatingVersionCombo = false;
        }

        ApplySelectedVersionFromCombo();
    }

    private static void ApplySelectedVersionFromCombo()
    {
        if (_currentConfig3 is null || _configVersions.Count == 0)
        {
            return;
        }

        var selectedIndex = _versionComboBox.SelectedItem;
        if (selectedIndex < 0 || selectedIndex >= _configVersions.Count)
        {
            selectedIndex = 0;
            _versionComboBox.SelectedItem = selectedIndex;
        }

        var version = _configVersions[selectedIndex];
        if (!_currentConfig3.Versions.TryGetValue(version, out var entry))
        {
            return;
        }

        _signature1Text.Text = entry.Sig1 ?? string.Empty;
        _signature2Text.Text = entry.Sig2 ?? string.Empty;
        _signature3Text.Text = entry.Sig3 ?? string.Empty;
        _versionComboBox.Text = version;
        AppendLog("已选择版本特征: " + version);
    }

    private static void ApplySearchResult(CallChainSearchResult result)
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
            AppendLog("未加载到原生 libcapstone, 已使用内置 lea/call 解析降级输出。");
        }

        if (result.DeleteMessagesChain is not null)
        {
            _deleteOffsetText.Text = NumericParser.FormatHexUnchecked(result.DeleteMessagesChain.RootCallRva);
            _deleteChainText.Text = result.DeleteMessagesChain.Format();
            AppendLog("DeleteMessages 调用链已搜索完毕。");
        }
        else
        {
            AppendLog("未在三层调用深度内找到 DeleteMessages 调用链。");
        }

        if (result.AddMessageToDbChain is not null)
        {
            _addDbOffsetText.Text = NumericParser.FormatHexUnchecked(result.AddMessageToDbChain.TargetCallRva);
            _addDbChainText.Text = result.AddMessageToDbChain.Format();
            AppendLog("CoAddMessageToDB 调用链已搜索完毕。");
        }
        else
        {
            AppendLog("未在三层调用深度内找到 CoAddMessageToDB 调用链。");
        }

        AppendLog("搜索完成, 结果已回填到偏移框。");
    }

    private static void AppendLocatedFunction(LocatedFunction function)
    {
        AppendLog(
            $"{function.Name}: stringFile={NumericParser.FormatHexUnchecked(function.StringFileOffset)}, stringRVA={NumericParser.FormatHexUnchecked(function.StringRva)}, leaFile={NumericParser.FormatHexUnchecked(function.LeaFileOffset)}, leaRVA={NumericParser.FormatHexUnchecked(function.LeaRva)}, funcRVA={NumericParser.FormatHexUnchecked(function.FunctionRva)}, insn={function.LeaInstructionText}");
    }

    private static void LoadConfigToUi(RevokeHookConfig config)
    {
        _deleteOffsetText.Text = NumericParser.FormatCompact(config.KeyFunc.DelMsgOffset);
        _addDbOffsetText.Text = NumericParser.FormatCompact(config.KeyFunc.Add2DBOffset);
        _autoRunCheck.Checked = config.Setting.AutoRun;
        _outputDebugCheck.Checked = config.Setting.OutputDebugMsg;
        _overTipCheck.Checked = config.Setting.OverTip;
        _antiRevokeSelfCheck.Checked = config.Setting.AntiRevokeSelf;
    }

    private static RevokeHookConfig ReadConfigFromUi()
    {
        _currentConfig.KeyFunc = new KeyFuncSection
        {
            DelMsgOffset = NumericParser.ParseInt(GetText(_deleteOffsetText)),
            Add2DBOffset = NumericParser.ParseInt(GetText(_addDbOffsetText))
        };
        _currentConfig.Setting = new SettingSection
        {
            AutoRun = _autoRunCheck.Checked,
            OutputDebugMsg = _outputDebugCheck.Checked,
            OverTip = _overTipCheck.Checked,
            AntiRevokeSelf = _antiRevokeSelfCheck.Checked,
            Ver = GetSelectedVersion()
        };

        return _currentConfig;
    }

    private static string GetSelectedVersion()
    {
        var selectedIndex = _versionComboBox.SelectedItem;
        if (selectedIndex >= 0 && selectedIndex < _configVersions.Count)
        {
            return _configVersions[selectedIndex];
        }

        return _versionComboBox.Text?.ToString() ?? string.Empty;
    }

    private static string GetText(TextField field)
    {
        return field.Text?.ToString() ?? string.Empty;
    }

    private static string NormalizeVersion(string version)
    {
        var parts = version.Split('.', StringSplitOptions.RemoveEmptyEntries);
        return string.Join('.', parts.Select(part => int.TryParse(part, out var value) ? value.ToString() : part));
    }

    private static string VersionSortKey(string version)
    {
        var parts = version.Split('.', StringSplitOptions.RemoveEmptyEntries)
            .Select(part => int.TryParse(part, out var value) ? value.ToString("D5") : part)
            .ToArray();
        return string.Join('.', parts);
    }

    private static void UpdateProgress(int percent, string message)
    {
        Application.MainLoop.Invoke(() =>
        {
            _progressBar.Fraction = Math.Clamp(percent, 0, 100) / 100f;
            _progressLabel.Text = message;
            _progressLabel.SetNeedsDisplay();
        });
    }

    private static void ShowMessage(string title, string message)
    {
        Application.MainLoop.Invoke(() => MessageBox.Query(72, 9, title, message, "OK"));
    }

    private static void ShowError(string title, string message)
    {
        Application.MainLoop.Invoke(() => MessageBox.ErrorQuery(70, 8, title, message, "OK"));
    }

    private static void ToggleButtons(bool enabled)
    {
        Application.MainLoop.Invoke(() =>
        {
            foreach (var button in Buttons)
            {
                button.Enabled = enabled;
            }
        });
    }

    private static void AppendLog(string message)
    {
        Application.MainLoop.Invoke(() =>
        {
            var current = _logText.Text?.ToString() ?? string.Empty;
            _logText.Text = current + $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] {message}{Environment.NewLine}";
            _logText.MoveEnd();
        });
    }
}
