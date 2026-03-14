using System.Threading.Tasks;
using System.Windows;
using RevokeHookUI.Services;

namespace RevokeHookUI;

public partial class ProgressWindow : Window
{
    public ProgressWindow(string title)
    {
        InitializeComponent();
        Title = title;
        TitleTextBlock.Text = title;
    }

    public void Report(CloudDownloadProgress progress)
    {
        MessageTextBlock.Text = progress.Message;
        DownloadProgressBar.IsIndeterminate = progress.IsIndeterminate;

        if (progress.Percentage is { } percentage)
        {
            DownloadProgressBar.Value = percentage;
            PercentTextBlock.Text = $"{percentage:F1}%";
            return;
        }

        PercentTextBlock.Text = string.Empty;
    }

    public Task DelayCloseAsync(int milliseconds)
    {
        return Task.Delay(milliseconds).ContinueWith(_ => Dispatcher.Invoke(Close));
    }
}
