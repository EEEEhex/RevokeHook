namespace RevokeHookUI.Models;

public class RevokeHookConfig
{
    public KeyFuncSection KeyFunc { get; set; } = new();

    public DelMsgSection DelMsg { get; set; } = new();

    public Add2DbSection Add2DB { get; set; } = new();

    public SettingSection Setting { get; set; } = new();
}

public class KeyFuncSection
{
    public int DelMsgOffset { get; set; }

    public int Add2DBOffset { get; set; }
}

public class DelMsgSection
{
    public int ArgMsgIndex { get; set; }

    public int OffsetWxIDFirst { get; set; }

    public int OffsetWxIDSecond { get; set; }

    public int OffsetWxIDThird { get; set; }
}

public class Add2DbSection
{
    public int ArgMsgIndex { get; set; }

    public int ArgBoolIndex { get; set; }

    public int OffsetRevokeXML { get; set; }

    public int OffsetSrvID { get; set; }
}

public class SettingSection
{
    public bool AutoRun { get; set; }

    public bool OverTip { get; set; }

    public bool AntiRevokeSelf { get; set; }

    public bool OutputDebugMsg { get; set; }

    public string Ver { get; set; } = string.Empty;
}
