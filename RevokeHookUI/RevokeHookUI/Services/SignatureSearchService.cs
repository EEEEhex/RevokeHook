using System.IO;
using System.Reflection.PortableExecutable;

namespace RevokeHookUI.Services;

public sealed class SignatureSearchResult
{
    public List<SignatureMatch> Matches { get; } = new();
}

public readonly record struct SignatureMatch(int BaseOffset, int AdjustedOffset, string PreviewHex);

public static class SignatureSearchService
{
    public static SignatureSearchResult Search(string pePath, string pattern, int delta)
    {
        if (string.IsNullOrWhiteSpace(pattern))
        {
            throw new InvalidOperationException("特征码不能为空。");
        }

        var patternBytes = ParsePattern(pattern);
        if (patternBytes.Length == 0)
        {
            throw new InvalidOperationException("特征码格式无效。");
        }

        using var stream = File.OpenRead(pePath);
        using var reader = new PEReader(stream);

        var textSection = reader.PEHeaders.SectionHeaders.FirstOrDefault(section => section.Name == ".text");
        if (textSection.Name != ".text")
        {
            throw new InvalidDataException("未找到 .text 节。");
        }

        stream.Position = textSection.PointerToRawData;
        var textBytes = new byte[textSection.SizeOfRawData];
        stream.ReadExactly(textBytes);

        var offsets = SundaySearch(textBytes, patternBytes);
        var result = new SignatureSearchResult();

        foreach (var offset in offsets)
        {
            var rva = textSection.VirtualAddress + offset;
            var adjustedOffset = rva + delta;
            var previewHex = ReadPreviewHex(textBytes, adjustedOffset - textSection.VirtualAddress, 5);
            result.Matches.Add(new SignatureMatch(rva, adjustedOffset, previewHex));
        }

        return result;
    }

    private static string ReadPreviewHex(ReadOnlySpan<byte> textBytes, int offsetInTextSection, int length)
    {
        if (offsetInTextSection < 0 || offsetInTextSection >= textBytes.Length)
        {
            return string.Empty;
        }

        var availableLength = Math.Min(length, textBytes.Length - offsetInTextSection);
        return string.Join(
            " ",
            textBytes.Slice(offsetInTextSection, availableLength).ToArray().Select(value => value.ToString("X2")));
    }

    private static int[] SundaySearch(ReadOnlySpan<byte> buffer, byte?[] pattern)
    {
        var result = new List<int>();
        var length = pattern.Length;
        if (buffer.Length < length)
        {
            return result.ToArray();
        }

        var lastOccurrence = Enumerable.Repeat(-1, 256).ToArray();
        var wildcardLast = -1;
        for (var index = 0; index < pattern.Length; index++)
        {
            if (pattern[index].HasValue)
            {
                lastOccurrence[pattern[index]!.Value] = index;
            }
            else
            {
                wildcardLast = index;
            }
        }

        for (var start = 0; start <= buffer.Length - length;)
        {
            var matched = true;
            for (var index = 0; index < length; index++)
            {
                if (pattern[index].HasValue && pattern[index]!.Value != buffer[start + index])
                {
                    matched = false;
                    break;
                }
            }

            if (matched)
            {
                result.Add(start);
            }

            if (start + length >= buffer.Length)
            {
                break;
            }

            var nextByte = buffer[start + length];
            var shiftIndex = lastOccurrence[nextByte];
            if (shiftIndex < 0)
            {
                shiftIndex = wildcardLast;
            }

            start += length - shiftIndex;
        }

        return result.ToArray();
    }

    private static byte?[] ParsePattern(string pattern)
    {
        return pattern
            .Split(' ', StringSplitOptions.RemoveEmptyEntries)
            .Select(token => token == "??" ? (byte?)null : Convert.ToByte(token, 16))
            .ToArray();
    }
}
