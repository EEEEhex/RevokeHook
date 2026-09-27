using System.IO;
using System.Text;
using RevokeHookTUI.Models;

namespace RevokeHookTUI.Services;

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
