using System.IO;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.ComTypes;
using Microsoft.Win32;

namespace RevokeHookUI.Services;

public static class WindowsSystemService
{
    public static string? TryGetWeChatVersion()
    {
        using var key = Registry.CurrentUser.OpenSubKey(@"Software\Tencent\Weixin");
        if (key is null)
        {
            return null;
        }

        if (key.GetValue("Version") is int versionValue && versionValue != 0)
        {
            var main = (versionValue >> 16) & 0xF;
            var sub = (versionValue >> 12) & 0xF;
            var third = (versionValue >> 8) & 0xF;
            var build = versionValue & 0xFF;
            return $"{main}.{sub}.{third}.{build}";
        }

        var installPath = key.GetValue("InstallPath") as string;
        if (string.IsNullOrWhiteSpace(installPath) || !Directory.Exists(installPath))
        {
            return null;
        }

        var versionDir = Directory.GetDirectories(installPath)
            .Select(Path.GetFileName)
            .Where(name => !string.IsNullOrWhiteSpace(name) && name.Contains('.'))
            .OrderByDescending(BuildVersionSortKey)
            .FirstOrDefault();

        return versionDir;
    }

    public static string? TryGetWeChatDllPath()
    {
        using var key = Registry.CurrentUser.OpenSubKey(@"Software\Tencent\Weixin");
        var installPath = key?.GetValue("InstallPath") as string;
        var version = TryGetWeChatVersion();

        if (string.IsNullOrWhiteSpace(installPath) || string.IsNullOrWhiteSpace(version))
        {
            return null;
        }

        var dllPath = Path.Combine(installPath, version, "Weixin.dll");
        return File.Exists(dllPath) ? dllPath : null;
    }

    public static void SetAutoRun(string valueName, bool enabled, string executablePath)
    {
        using var runKey = Registry.CurrentUser.OpenSubKey(
            @"Software\Microsoft\Windows\CurrentVersion\Run",
            writable: true);

        if (runKey is null)
        {
            throw new InvalidOperationException("无法打开启动项注册表。");
        }

        if (!enabled)
        {
            runKey.DeleteValue(valueName, false);
            return;
        }

        runKey.SetValue(valueName, $"\"{executablePath}\"");
    }

    public static void CreateShortcut(string shortcutPath, string targetPath, string workingDirectory)
    {
        if (!File.Exists(targetPath))
        {
            throw new FileNotFoundException("未找到目标程序 RevokeInject.exe。", targetPath);
        }

        var shellLinkType = Type.GetTypeFromCLSID(new Guid("00021401-0000-0000-C000-000000000046"))
            ?? throw new InvalidOperationException("无法创建 ShellLink COM 对象。");
        var shellLink = (IShellLinkW)Activator.CreateInstance(shellLinkType)!;
        shellLink.SetPath(targetPath);
        shellLink.SetWorkingDirectory(workingDirectory);

        var persistFile = (IPersistFile)shellLink;
        persistFile.Save(shortcutPath, false);
    }

    private static string BuildVersionSortKey(string? version)
    {
        if (string.IsNullOrWhiteSpace(version))
        {
            return string.Empty;
        }

        return string.Join(
            '.',
            version.Split('.', StringSplitOptions.RemoveEmptyEntries)
                .Select(part => int.TryParse(part, out var value) ? value.ToString("D5") : part));
    }

    [ComImport]
    [InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    [Guid("000214F9-0000-0000-C000-000000000046")]
    private interface IShellLinkW
    {
        void GetPath(IntPtr pszFile, int cch, IntPtr pfd, int fFlags);
        void GetIDList(out IntPtr ppidl);
        void SetIDList(IntPtr pidl);
        void GetDescription(IntPtr pszName, int cch);
        void SetDescription([MarshalAs(UnmanagedType.LPWStr)] string pszName);
        void GetWorkingDirectory(IntPtr pszDir, int cch);
        void SetWorkingDirectory([MarshalAs(UnmanagedType.LPWStr)] string pszDir);
        void GetArguments(IntPtr pszArgs, int cch);
        void SetArguments([MarshalAs(UnmanagedType.LPWStr)] string pszArgs);
        void GetHotkey(out short pwHotkey);
        void SetHotkey(short wHotkey);
        void GetShowCmd(out int piShowCmd);
        void SetShowCmd(int iShowCmd);
        void GetIconLocation(IntPtr pszIconPath, int cch, out int piIcon);
        void SetIconLocation([MarshalAs(UnmanagedType.LPWStr)] string pszIconPath, int iIcon);
        void SetRelativePath([MarshalAs(UnmanagedType.LPWStr)] string pszPathRel, int dwReserved);
        void Resolve(IntPtr hwnd, int fFlags);
        void SetPath([MarshalAs(UnmanagedType.LPWStr)] string pszFile);
    }
}
