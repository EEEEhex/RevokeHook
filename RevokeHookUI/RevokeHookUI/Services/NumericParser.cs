using System.Globalization;

namespace RevokeHookUI.Services;

public static class NumericParser
{
    public static int ParseInt(string? text)
    {
        if (string.IsNullOrWhiteSpace(text))
        {
            return 0;
        }

        var value = text.Trim();
        if (value.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
        {
            return int.TryParse(value[2..], NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var hexValue)
                ? hexValue
                : 0;
        }

        return int.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var intValue)
            ? intValue
            : 0;
    }

    public static bool ParseBool(string? text)
    {
        return bool.TryParse(text, out var result) && result;
    }

    public static string FormatHex(int value)
    {
        return $"0x{value:X}";
    }

    public static string FormatCompact(int value)
    {
        return value == 0 ? "0" : FormatHex(value);
    }
}
