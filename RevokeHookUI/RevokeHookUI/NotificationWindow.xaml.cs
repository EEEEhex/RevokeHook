using System;
using System.Windows;
using System.Windows.Threading;

namespace RevokeHookUI;

public partial class NotificationWindow : Window
{
    private readonly DispatcherTimer _closeTimer = new() { Interval = TimeSpan.FromSeconds(4) };

    public NotificationWindow(string title, string content)
    {
        InitializeComponent();
        TitleTextBlock.Text = title;
        ContentTextBlock.Text = content;
        Loaded += NotificationWindow_Loaded;
        _closeTimer.Tick += CloseTimer_Tick;
    }

    private void NotificationWindow_Loaded(object sender, RoutedEventArgs e)
    {
        var workArea = SystemParameters.WorkArea;
        Left = workArea.Right - Width - 16;
        Top = workArea.Bottom - Height - 16;
        _closeTimer.Start();
    }

    private void CloseTimer_Tick(object? sender, EventArgs e)
    {
        _closeTimer.Stop();
        Close();
    }
}
