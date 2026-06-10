using System.ComponentModel;
using System.Diagnostics;
using System.Text;

namespace RevokeHookTUI.Services;

public sealed record FlatpakWeChatInfo(
    bool Installed,
    string? Version,
    string? InstallLocation,
    string? BinaryPath,
    string? Detail);

public sealed record DesktopShortcutResult(string DesktopFilePath, string ExecCommand);

public static class FlatpakWeChatService
{
    private const string WeChatAppId = "com.tencent.WeChat";

    public static async Task<FlatpakWeChatInfo> DetectAsync(CancellationToken cancellationToken = default)
    {
        var infoResult = await RunProcessAsync("flatpak", $"info {WeChatAppId}", cancellationToken);
        if (infoResult.ExitCode != 0)
        {
            var detail = infoResult.Stderr.Trim();
            return new FlatpakWeChatInfo(false, null, null, null, detail);
        }

        var locationResult = await RunProcessAsync(
            "flatpak",
            $"info --show-location {WeChatAppId}",
            cancellationToken);
        var installLocation = locationResult.ExitCode == 0
            ? locationResult.Stdout.Trim()
            : null;
        var binaryPath = string.IsNullOrWhiteSpace(installLocation)
            ? null
            : Path.Combine(installLocation, "files", "extra", "wechat", "wechat");

        return new FlatpakWeChatInfo(
            true,
            ParseVersion(infoResult.Stdout),
            string.IsNullOrWhiteSpace(installLocation) ? null : installLocation,
            binaryPath,
            locationResult.ExitCode == 0 ? null : locationResult.Stderr.Trim());
    }

    public static async Task<DesktopShortcutResult> CreateShortcutAsync(
        string baseDirectory,
        CancellationToken cancellationToken = default)
    {
        var info = await DetectAsync(cancellationToken);
        if (!info.Installed)
        {
            throw new NotSupportedException("暂不支持");
        }

        var normalizedBaseDirectory = Path.GetFullPath(baseDirectory);
        var injectorPath = Path.Combine(normalizedBaseDirectory, "injector");
        var hookPath = Path.Combine(normalizedBaseDirectory, "librevokehook.so");
        var iniPath = Path.Combine(normalizedBaseDirectory, "RevokeHook.ini");
        var desktopDirectory = GetDesktopDirectory();
        Directory.CreateDirectory(desktopDirectory);

        var execCommand =
            $"{QuoteDesktopExec(injectorPath)} -f {WeChatAppId} -s {QuoteDesktopExec(hookPath)} {QuoteDesktopExec("--env=REVOKEHOOK_INI=" + iniPath)}";
        var desktopPath = Path.Combine(desktopDirectory, "WeChatRevoke.desktop");
        var content = string.Join('\n', new[]
        {
            "[Desktop Entry]",
            "Type=Application",
            "Name=WeChatRevoke",
            "Name[zh_CN]=微信Revoke",
            "Comment=Start WeChat with RevokeHook",
            $"Exec={execCommand}",
            $"Path={EscapeDesktopValue(normalizedBaseDirectory)}",
            "Terminal=false",
            "StartupNotify=false",
            "Categories=Network;InstantMessaging;"
        }) + "\n";

        await File.WriteAllTextAsync(desktopPath, content, new UTF8Encoding(false), cancellationToken);
        TryMarkExecutable(desktopPath);

        return new DesktopShortcutResult(desktopPath, execCommand);
    }

    private static string? ParseVersion(string flatpakInfo)
    {
        using var reader = new StringReader(flatpakInfo);
        string? line;
        while ((line = reader.ReadLine()) is not null)
        {
            var trimmed = line.Trim();
            if (!trimmed.StartsWith("Version:", StringComparison.OrdinalIgnoreCase) &&
                !trimmed.StartsWith("Version：", StringComparison.OrdinalIgnoreCase) &&
                !trimmed.StartsWith("版本:", StringComparison.OrdinalIgnoreCase) &&
                !trimmed.StartsWith("版本：", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            var separatorIndex = trimmed.IndexOfAny(new[] { ':', '：' });
            if (separatorIndex < 0 || separatorIndex + 1 >= trimmed.Length)
            {
                continue;
            }

            var version = trimmed[(separatorIndex + 1)..].Trim();
            if (!string.IsNullOrWhiteSpace(version))
            {
                return version;
            }
        }

        return null;
    }

    private static string GetDesktopDirectory()
    {
        var home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        if (string.IsNullOrWhiteSpace(home))
        {
            home = Environment.GetEnvironmentVariable("HOME") ?? ".";
        }

        var configuredDesktop = ReadConfiguredDesktopDirectory(home);
        if (!string.IsNullOrWhiteSpace(configuredDesktop))
        {
            return configuredDesktop;
        }

        var chineseDesktop = Path.Combine(home, "桌面");
        if (Directory.Exists(chineseDesktop))
        {
            return chineseDesktop;
        }

        var englishDesktop = Path.Combine(home, "Desktop");
        return Directory.Exists(englishDesktop) ? englishDesktop : chineseDesktop;
    }

    private static string? ReadConfiguredDesktopDirectory(string home)
    {
        var userDirsPath = Path.Combine(home, ".config", "user-dirs.dirs");
        if (!File.Exists(userDirsPath))
        {
            return null;
        }

        foreach (var line in File.ReadLines(userDirsPath))
        {
            var trimmed = line.Trim();
            if (!trimmed.StartsWith("XDG_DESKTOP_DIR=", StringComparison.Ordinal))
            {
                continue;
            }

            var value = trimmed["XDG_DESKTOP_DIR=".Length..].Trim().Trim('"');
            if (string.IsNullOrWhiteSpace(value))
            {
                continue;
            }

            return value.Replace("$HOME", home, StringComparison.Ordinal);
        }

        return null;
    }

    private static string QuoteDesktopExec(string value)
    {
        return $"\"{EscapeDesktopValue(value)}\"";
    }

    private static string EscapeDesktopValue(string value)
    {
        return value
            .Replace("\\", "\\\\", StringComparison.Ordinal)
            .Replace("\"", "\\\"", StringComparison.Ordinal)
            .Replace("$", "\\$", StringComparison.Ordinal)
            .Replace("`", "\\`", StringComparison.Ordinal);
    }

    private static void TryMarkExecutable(string path)
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        try
        {
            using var process = Process.Start(new ProcessStartInfo
            {
                FileName = "chmod",
                ArgumentList = { "+x", path },
                UseShellExecute = false,
                CreateNoWindow = true
            });
            process?.WaitForExit(2000);
        }
        catch
        {
            // The desktop file is still usable if chmod is unavailable; the file manager may ask for confirmation.
        }
    }

    private static async Task<ProcessResult> RunProcessAsync(
        string fileName,
        string arguments,
        CancellationToken cancellationToken)
    {
        try
        {
            using var process = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = fileName,
                    Arguments = arguments,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                }
            };

            process.Start();
            var stdoutTask = process.StandardOutput.ReadToEndAsync(cancellationToken);
            var stderrTask = process.StandardError.ReadToEndAsync(cancellationToken);
            await process.WaitForExitAsync(cancellationToken);
            return new ProcessResult(process.ExitCode, await stdoutTask, await stderrTask);
        }
        catch (Exception ex) when (ex is Win32Exception or FileNotFoundException)
        {
            return new ProcessResult(-1, string.Empty, ex.Message);
        }
    }

    private sealed record ProcessResult(int ExitCode, string Stdout, string Stderr);
}
