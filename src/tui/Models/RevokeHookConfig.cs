namespace RevokeHookTUI.Models;

public class RevokeHookConfig
{
    public KeyFuncSection KeyFunc { get; set; } = new();

    public SettingSection Setting { get; set; } = new();
}

public class KeyFuncSection
{
    public int DelMsgOffset { get; set; }

    public int Add2DBOffset { get; set; }
}

public class SettingSection
{
    public bool AutoRun { get; set; }

    public bool OverTip { get; set; }

    public bool AntiRevokeSelf { get; set; }

    public bool OutputDebugMsg { get; set; }

    public string Ver { get; set; } = string.Empty;
}
