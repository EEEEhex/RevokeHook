using System.IO;
using System.Threading.Tasks;
using System.Windows;
using RevokeHookUI.Services;

namespace RevokeHookUI;

public partial class App : Application
{
    protected override async void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        ShutdownMode = ShutdownMode.OnLastWindowClose;
        Directory.SetCurrentDirectory(AppContext.BaseDirectory);

        var options = CliOptions.Parse(e.Args);

        if (options.UpdateConfig)
        {
            await RunConfigUpdateModeAsync();
            return;
        }

        if (!string.IsNullOrWhiteSpace(options.MessageTitle) || !string.IsNullOrWhiteSpace(options.MessageContent))
        {
            var notificationWindow = new NotificationWindow(
                options.MessageTitle ?? "RevokeHook",
                options.MessageContent ?? string.Empty);
            notificationWindow.Show();
            return;
        }

        var mainWindow = new MainWindow();
        MainWindow = mainWindow;
        mainWindow.Show();
    }

    private async Task RunConfigUpdateModeAsync()
    {
        var progressWindow = new ProgressWindow("云端配置更新");
        progressWindow.Show();

        try
        {
            var progress = new Progress<CloudDownloadProgress>(progressWindow.Report);
            await CloudConfigService.DownloadLatestConfigAsync(
                Path.Combine(AppContext.BaseDirectory, "Config2.json"),
                progress);

            progressWindow.Report(new CloudDownloadProgress("最新 Config2.json 下载完成。", 100, false));
            await progressWindow.DelayCloseAsync(800);
            Shutdown(0);
        }
        catch (Exception ex)
        {
            progressWindow.Report(new CloudDownloadProgress("配置更新失败: " + ex.Message, null, false));
            await progressWindow.DelayCloseAsync(1800);
            Shutdown(1);
        }
    }
}
