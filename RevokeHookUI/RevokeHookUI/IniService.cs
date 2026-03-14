using System.IO;
using System.Text;
using RevokeHookUI.Models;

namespace RevokeHookUI.Services;

public static class IniService
{
    public static RevokeHookConfig Load(string path)
    {
        var config = new RevokeHookConfig();
        if (!File.Exists(path))
        {
            return config;
        }

        var currentSection = string.Empty;
        foreach (var rawLine in File.ReadAllLines(path, Encoding.UTF8))
        {
            var line = rawLine.Trim();
            if (string.IsNullOrWhiteSpace(line) || line.StartsWith(';') || line.StartsWith('#'))
            {
                continue;
            }

            if (line.StartsWith('[') && line.EndsWith(']'))
            {
                currentSection = line[1..^1];
                continue;
            }

            var index = line.IndexOf('=');
            if (index <= 0)
            {
                continue;
            }

            var key = line[..index].Trim();
            var value = line[(index + 1)..].Trim();
            ApplyValue(config, currentSection, key, value);
        }

        return config;
    }

    public static void Save(string path, RevokeHookConfig config)
    {
        var builder = new StringBuilder();

        builder.AppendLine("[KeyFunc]");
        builder.AppendLine($"DelMsgOffset={config.KeyFunc.DelMsgOffset}");
        builder.AppendLine($"Add2DBOffset={config.KeyFunc.Add2DBOffset}");
        builder.AppendLine();

        builder.AppendLine("[DelMsg]");
        builder.AppendLine($"ArgMsgIndex={config.DelMsg.ArgMsgIndex}");
        builder.AppendLine($"OffsetWxIDFirst={config.DelMsg.OffsetWxIDFirst}");
        builder.AppendLine($"OffsetWxIDSecond={config.DelMsg.OffsetWxIDSecond}");
        builder.AppendLine($"OffsetWxIDThird={config.DelMsg.OffsetWxIDThird}");
        builder.AppendLine();

        builder.AppendLine("[Add2DB]");
        builder.AppendLine($"ArgMsgIndex={config.Add2DB.ArgMsgIndex}");
        builder.AppendLine($"ArgBoolIndex={config.Add2DB.ArgBoolIndex}");
        builder.AppendLine($"OffsetRevokeXML={config.Add2DB.OffsetRevokeXML}");
        builder.AppendLine($"OffsetSrvID={config.Add2DB.OffsetSrvID}");
        builder.AppendLine();

        builder.AppendLine("[Setting]");
        builder.AppendLine($"AutoRun={config.Setting.AutoRun.ToString().ToLowerInvariant()}");
        builder.AppendLine($"OverTip={config.Setting.OverTip.ToString().ToLowerInvariant()}");
        builder.AppendLine($"AntiRevokeSelf={config.Setting.AntiRevokeSelf.ToString().ToLowerInvariant()}");
        builder.AppendLine($"OutputDebugMsg={config.Setting.OutputDebugMsg.ToString().ToLowerInvariant()}");
        builder.AppendLine($"Ver={config.Setting.Ver}");

        File.WriteAllText(path, builder.ToString(), new UTF8Encoding(false));
    }

    private static void ApplyValue(RevokeHookConfig config, string section, string key, string value)
    {
        switch (section)
        {
            case "BP":
            case "KeyFunc":
                if (key == "DelMsgOffset")
                {
                    config.KeyFunc.DelMsgOffset = NumericParser.ParseInt(value);
                }
                else if (key == "Add2DBOffset")
                {
                    config.KeyFunc.Add2DBOffset = NumericParser.ParseInt(value);
                }

                break;
            case "DelMsg":
                if (key == "ArgMsgIndex")
                {
                    config.DelMsg.ArgMsgIndex = NumericParser.ParseInt(value);
                }
                else if (key == "OffsetWxIDFirst")
                {
                    config.DelMsg.OffsetWxIDFirst = NumericParser.ParseInt(value);
                }
                else if (key == "OffsetWxIDSecond")
                {
                    config.DelMsg.OffsetWxIDSecond = NumericParser.ParseInt(value);
                }
                else if (key == "OffsetWxIDThird")
                {
                    config.DelMsg.OffsetWxIDThird = NumericParser.ParseInt(value);
                }

                break;
            case "Add2DB":
                if (key == "ArgMsgIndex")
                {
                    config.Add2DB.ArgMsgIndex = NumericParser.ParseInt(value);
                }
                else if (key == "ArgBoolIndex")
                {
                    config.Add2DB.ArgBoolIndex = NumericParser.ParseInt(value);
                }
                else if (key == "OffsetRevokeXML")
                {
                    config.Add2DB.OffsetRevokeXML = NumericParser.ParseInt(value);
                }
                else if (key == "OffsetSrvID")
                {
                    config.Add2DB.OffsetSrvID = NumericParser.ParseInt(value);
                }

                break;
            case "Setting":
                if (key == "AutoRun")
                {
                    config.Setting.AutoRun = NumericParser.ParseBool(value);
                }
                else if (key == "OverTip")
                {
                    config.Setting.OverTip = NumericParser.ParseBool(value);
                }
                else if (key == "AntiRevokeSelf")
                {
                    config.Setting.AntiRevokeSelf = NumericParser.ParseBool(value);
                }
                else if (key == "OutputDebugMsg")
                {
                    config.Setting.OutputDebugMsg = NumericParser.ParseBool(value);
                }
                else if (key == "Ver")
                {
                    config.Setting.Ver = value;
                }

                break;
        }
    }
}
