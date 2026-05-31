using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Globalization;
using System.IO;
using System.Reflection.PortableExecutable;
using System.Runtime.InteropServices;
using System.Text;

namespace RevokeHookUI.Services;

public sealed record CallChainSearchRequest(string Signature1Hex, string Signature2Hex, string Signature3Hex);

public sealed record CallChainSearchProgress(int Percent, string Message);

public sealed class CallChainSearchResult
{
    public LocatedFunction OriginFunction { get; init; } = LocatedFunction.Empty("CoReplaceOriginMessageByRevoke");

    public LocatedFunction DeleteMessagesFunction { get; init; } = LocatedFunction.Empty("DeleteMessages");

    public LocatedFunction AddMessageToDbFunction { get; init; } = LocatedFunction.Empty("CoAddMessageToDB");

    public CallChainResult? DeleteMessagesChain { get; init; }

    public CallChainResult? AddMessageToDbChain { get; init; }

    public bool UsedNativeCapstone { get; init; }

    public IReadOnlyDictionary<string, int> CandidateCounts { get; init; } = new Dictionary<string, int>();
}

public sealed record LocatedFunction(
    string Name,
    uint StringFileOffset,
    uint StringRva,
    uint LeaFileOffset,
    uint LeaRva,
    uint FunctionRva,
    string LeaInstructionText)
{
    public static LocatedFunction Empty(string name)
    {
        return new LocatedFunction(name, 0, 0, 0, 0, 0, string.Empty);
    }
}

public sealed record CallChainResult(
    string TargetName,
    uint RootCallRva,
    IReadOnlyList<CallInstruction> Chain,
    string EvidenceText = "")
{
    public uint TargetCallRva => Chain.LastOrDefault(call => call.IsDirectTarget)?.Rva ?? RootCallRva;

    public string Format()
    {
        var builder = new StringBuilder();
        builder.AppendLine($"{TargetName}: {NumericParser.FormatHexUnchecked(RootCallRva)}");
        if (!string.IsNullOrWhiteSpace(EvidenceText))
        {
            builder.AppendLine($"  {EvidenceText}");
        }

        foreach (var call in Chain)
        {
            var marker = call.IsDirectTarget ? " <- target-call" : string.Empty;
            builder.AppendLine($"  {NumericParser.FormatHexUnchecked(call.Rva)}: {call.Text}{marker}");
        }

        return builder.ToString().TrimEnd();
    }
}

public sealed record CallInstruction(uint Rva, uint CallerRva, uint TargetRva, string Text, bool IsDirectTarget = false);

public static class CallChainSearchService
{
    private const int MaxCallDepth = 3;

    public static CallChainSearchResult Search(
        string pePath,
        CallChainSearchRequest request,
        IProgress<CallChainSearchProgress>? progress = null)
    {
        if (!File.Exists(pePath))
        {
            throw new FileNotFoundException("目标文件不存在。", pePath);
        }

        progress?.Report(new CallChainSearchProgress(5, "读取 PE 文件..."));
        var image = PeImage.Load(pePath);
        var text = image.GetRequiredSection(".text");
        var rdata = image.GetRequiredSection(".rdata");

        progress?.Report(new CallChainSearchProgress(15, "解析三个加密字符串的 16 进制值..."));
        var signatures = new[]
        {
            new SignatureTarget("CoReplaceOriginMessageByRevoke", ParseHexBytes(request.Signature1Hex)),
            new SignatureTarget("DeleteMessages", ParseHexBytes(request.Signature2Hex)),
            new SignatureTarget("CoAddMessageToDB", ParseHexBytes(request.Signature3Hex))
        };

        progress?.Report(new CallChainSearchProgress(25, "在 .rdata 并行定位字符串..."));
        var stringMatches = LocateStringMatches(rdata, signatures);

        progress?.Report(new CallChainSearchProgress(45, "在 .text 并行定位 lea 引用..."));
        using var disassembler = X64Disassembler.Create();
        var functionCandidates = LocateFunctionCandidatesFromLea(image, text, stringMatches, disassembler);

        progress?.Report(new CallChainSearchProgress(65, "解析调用图并搜索三层调用链..."));
        var callScanner = new FunctionCallScanner(image, text, disassembler);
        var selected = SelectFunctionsByCallChains(callScanner, functionCandidates);

        progress?.Report(new CallChainSearchProgress(100, "搜索完成。"));
        return new CallChainSearchResult
        {
            OriginFunction = selected.Origin,
            DeleteMessagesFunction = selected.DeleteMessages,
            AddMessageToDbFunction = selected.AddMessageToDb,
            DeleteMessagesChain = selected.DeleteMessagesChain,
            AddMessageToDbChain = selected.AddMessageToDbChain,
            UsedNativeCapstone = disassembler.UsedNativeCapstone,
            CandidateCounts = functionCandidates.ToDictionary(pair => pair.Key, pair => pair.Value.Count, StringComparer.Ordinal)
        };
    }

    private static Dictionary<string, List<StringMatch>> LocateStringMatches(
        PeSection rdata,
        IReadOnlyList<SignatureTarget> signatures)
    {
        var results = new ConcurrentDictionary<string, List<StringMatch>>();

        Parallel.ForEach(signatures, signature =>
        {
            var matches = ParallelSearch(rdata.Bytes, signature.Bytes);
            if (matches.Count == 0)
            {
                throw new InvalidOperationException($"未在 .rdata 找到 {signature.Name} 的字符串特征。");
            }

            results[signature.Name] = matches
                .Select(offset => new StringMatch(
                    checked(rdata.RawPointer + (uint)offset),
                    checked(rdata.VirtualAddress + (uint)offset)))
                .ToList();
        });

        return results.ToDictionary(pair => pair.Key, pair => pair.Value, StringComparer.Ordinal);
    }

    private static Dictionary<string, List<LocatedFunction>> LocateFunctionCandidatesFromLea(
        PeImage image,
        PeSection text,
        IReadOnlyDictionary<string, List<StringMatch>> stringMatches,
        X64Disassembler disassembler)
    {
        var results = new ConcurrentDictionary<string, List<LocatedFunction>>();

        Parallel.ForEach(stringMatches, pair =>
        {
            var locatedFunctions = new ConcurrentBag<LocatedFunction>();

            Parallel.ForEach(pair.Value, stringMatch =>
            {
                foreach (var leaRva in FindRipRelativeLeasToTarget(text, stringMatch.Rva))
                {
                    var function = image.FindFunction(leaRva);
                    if (function is null)
                    {
                        continue;
                    }

                    var leaOffset = checked((int)(leaRva - text.VirtualAddress));
                    var leaText = disassembler.DisassembleOne(text.Bytes.Span, leaOffset, leaRva, 16)
                        ?? FormatFallbackLea(text.Bytes.Span, leaOffset, leaRva);

                    locatedFunctions.Add(new LocatedFunction(
                        pair.Key,
                        stringMatch.FileOffset,
                        stringMatch.Rva,
                        checked(text.RawPointer + (leaRva - text.VirtualAddress)),
                        leaRva,
                        function.Value.BeginRva,
                        leaText));
                }
            });

            var candidates = locatedFunctions
                .GroupBy(candidate => candidate.FunctionRva)
                .Select(group => group.OrderBy(candidate => candidate.LeaRva).First())
                .OrderBy(candidate => candidate.FunctionRva)
                .ThenBy(candidate => candidate.LeaRva)
                .ToList();
            if (candidates.Count == 0)
            {
                throw new InvalidOperationException($"未在 .text 找到引用 {pair.Key} 字符串的 lea 指令。");
            }

            results[pair.Key] = candidates;
        });

        return results.ToDictionary(pair => pair.Key, pair => pair.Value, StringComparer.Ordinal);
    }

    private static List<uint> FindRipRelativeLeasToTarget(PeSection text, uint targetRva)
    {
        var matches = new ConcurrentBag<uint>();
        var bytes = text.Bytes;
        var maxStart = bytes.Length - 7;

        if (maxStart < 0)
        {
            return new List<uint>();
        }

        Parallel.ForEach(Partitioner.Create(0, maxStart + 1), range =>
        {
            var span = bytes.Span;
            for (var index = range.Item1; index < range.Item2; index++)
            {
                var rex = span[index];
                if ((rex != 0x48 && rex != 0x4C) || span[index + 1] != 0x8D)
                {
                    continue;
                }

                var modrm = span[index + 2];
                var isRipRelative = (modrm & 0xC7) == 0x05 && (rex & 0x01) == 0;
                if (!isRipRelative)
                {
                    continue;
                }

                var disp = BinaryPrimitives.ReadInt32LittleEndian(span.Slice(index + 3, 4));
                var instructionRva = text.VirtualAddress + (uint)index;
                var computedTarget = unchecked((uint)(instructionRva + 7 + disp));
                if (computedTarget == targetRva)
                {
                    matches.Add(instructionRva);
                }
            }
        });

        return matches.OrderBy(value => value).ToList();
    }

    private static CallChainResult? FindChain(
        FunctionCallScanner scanner,
        uint originFunctionRva,
        uint targetFunctionRva,
        string targetName,
        uint minRootCallRva = 0)
    {
        foreach (var rootCall in scanner.GetCalls(originFunctionRva)
                     .Where(call => call.Rva > minRootCallRva)
                     .OrderBy(call => call.Rva))
        {
            var path = new List<CallInstruction> { rootCall };
            if (rootCall.TargetRva == targetFunctionRva ||
                SearchNested(scanner, rootCall.TargetRva, targetFunctionRva, MaxCallDepth - 1, path, new HashSet<uint> { originFunctionRva }))
            {
                MarkTargetCall(path, targetFunctionRva);
                return new CallChainResult(targetName, rootCall.Rva, path);
            }
        }

        return null;
    }

    private static CallChainResult? FindDeleteChainWithZeroArgumentSetup(
        FunctionCallScanner scanner,
        uint originFunctionRva,
        uint deleteMessagesFunctionRva)
    {
        foreach (var rootCall in scanner.GetCalls(originFunctionRva).OrderBy(call => call.Rva))
        {
            var path = new List<CallInstruction> { rootCall };
            if (rootCall.TargetRva != deleteMessagesFunctionRva &&
                !SearchNested(scanner, rootCall.TargetRva, deleteMessagesFunctionRva, MaxCallDepth - 1, path, new HashSet<uint> { originFunctionRva }))
            {
                continue;
            }

            if (!scanner.TryFindZeroArgumentSetupBeforeCall(rootCall.CallerRva, rootCall.Rva, out var evidence))
            {
                continue;
            }

            var deleteCall = path.LastOrDefault(call => call.TargetRva == deleteMessagesFunctionRva);
            if (deleteCall is not null)
            {
                MarkTargetCall(path, deleteMessagesFunctionRva);
                return new CallChainResult(
                    "DeleteMessages",
                    rootCall.Rva,
                    path,
                    $"zero-arg-insn: {NumericParser.FormatHexUnchecked(evidence.Rva)}: {evidence.Text}");
            }
        }

        return null;
    }

    private static void MarkTargetCall(List<CallInstruction> path, uint targetFunctionRva)
    {
        for (var index = 0; index < path.Count; index++)
        {
            var call = path[index];
            if (call.TargetRva == targetFunctionRva)
            {
                path[index] = call with { IsDirectTarget = true };
                return;
            }
        }
    }

    private static SelectedFunctions SelectFunctionsByCallChains(
        FunctionCallScanner scanner,
        IReadOnlyDictionary<string, List<LocatedFunction>> candidates)
    {
        var origins = candidates["CoReplaceOriginMessageByRevoke"];
        var deleteMessagesCandidates = candidates["DeleteMessages"];
        var addMessageToDbCandidates = candidates["CoAddMessageToDB"];

        SelectedFunctions? bestPartial = null;
        foreach (var origin in origins)
        {
            foreach (var deleteMessages in deleteMessagesCandidates)
            {
                var deleteChain = FindDeleteChainWithZeroArgumentSetup(
                    scanner,
                    origin.FunctionRva,
                    deleteMessages.FunctionRva);

                foreach (var addMessageToDb in addMessageToDbCandidates)
                {
                    var addChain = deleteChain is null
                        ? null
                        : FindChain(
                            scanner,
                            origin.FunctionRva,
                            addMessageToDb.FunctionRva,
                            "CoAddMessageToDB",
                            deleteChain.RootCallRva);
                    if (deleteChain is not null && addChain is not null)
                    {
                        return new SelectedFunctions(origin, deleteMessages, addMessageToDb, deleteChain, addChain);
                    }

                    bestPartial ??= new SelectedFunctions(origin, deleteMessages, addMessageToDb, deleteChain, addChain);
                    if (deleteChain is not null || addChain is not null)
                    {
                        bestPartial = new SelectedFunctions(origin, deleteMessages, addMessageToDb, deleteChain, addChain);
                    }
                }
            }
        }

        return bestPartial ?? new SelectedFunctions(
            origins[0],
            deleteMessagesCandidates[0],
            addMessageToDbCandidates[0],
            null,
            null);
    }

    private static bool SearchNested(
        FunctionCallScanner scanner,
        uint functionRva,
        uint targetFunctionRva,
        int remainingDepth,
        List<CallInstruction> path,
        HashSet<uint> visitedFunctions)
    {
        if (remainingDepth <= 0 || !visitedFunctions.Add(functionRva))
        {
            return false;
        }

        foreach (var call in scanner.GetCalls(functionRva).OrderBy(item => item.Rva))
        {
            path.Add(call);
            if (call.TargetRva == targetFunctionRva ||
                SearchNested(scanner, call.TargetRva, targetFunctionRva, remainingDepth - 1, path, visitedFunctions))
            {
                return true;
            }

            path.RemoveAt(path.Count - 1);
        }

        visitedFunctions.Remove(functionRva);
        return false;
    }

    private static List<int> ParallelSearch(ReadOnlyMemory<byte> haystack, byte[] needle)
    {
        if (needle.Length == 0)
        {
            throw new InvalidOperationException("字符串特征不能为空。");
        }

        if (haystack.Length < needle.Length)
        {
            return new List<int>();
        }

        var matches = new ConcurrentBag<int>();
        var maxStart = haystack.Length - needle.Length;
        Parallel.ForEach(Partitioner.Create(0, maxStart + 1), range =>
        {
            for (var index = range.Item1; index < range.Item2; index++)
            {
                if (haystack.Span.Slice(index, needle.Length).SequenceEqual(needle))
                {
                    matches.Add(index);
                }
            }
        });

        return matches.OrderBy(value => value).ToList();
    }

    private static byte[] ParseHexBytes(string text)
    {
        if (string.IsNullOrWhiteSpace(text))
        {
            throw new InvalidOperationException("字符串特征不能为空。");
        }

        var normalized = text
            .Replace("0x", string.Empty, StringComparison.OrdinalIgnoreCase)
            .Replace("\\x", string.Empty, StringComparison.OrdinalIgnoreCase)
            .Replace(",", " ")
            .Replace(";", " ")
            .Replace("-", " ");

        var tokens = normalized.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
        string[] byteTokens;
        if (tokens.Length == 1 && tokens[0].Length > 2)
        {
            if ((tokens[0].Length & 1) != 0)
            {
                throw new FormatException("连续 16 进制字符串长度必须为偶数。");
            }

            byteTokens = Enumerable.Range(0, tokens[0].Length / 2)
                .Select(index => tokens[0].Substring(index * 2, 2))
                .ToArray();
        }
        else
        {
            byteTokens = tokens;
        }

        return byteTokens.Select(token =>
        {
            if (token == "??")
            {
                throw new FormatException("字符串特征必须是明确的 16 进制字节, 不支持 ?? 通配符。");
            }

            return byte.Parse(token, NumberStyles.HexNumber, CultureInfo.InvariantCulture);
        }).ToArray();
    }

    private static string FormatFallbackLea(ReadOnlySpan<byte> bytes, int offset, uint rva)
    {
        if (offset < 0 || offset + 7 > bytes.Length)
        {
            return "lea";
        }

        var disp = BinaryPrimitives.ReadInt32LittleEndian(bytes.Slice(offset + 3, 4));
        var target = unchecked((uint)(rva + 7 + disp));
        var regIndex = ((bytes[offset + 2] >> 3) & 0x7) | ((bytes[offset] & 0x04) != 0 ? 8 : 0);
        var registerName = X64RegisterNames[regIndex];
        var displacement = disp == int.MinValue ? "0x80000000" : $"0x{Math.Abs(disp):X}";
        return $"lea {registerName}, [rip {(disp < 0 ? "-" : "+")} {displacement}] ; {NumericParser.FormatHexUnchecked(target)}";
    }

    private sealed record SignatureTarget(string Name, byte[] Bytes);

    private sealed record StringMatch(uint FileOffset, uint Rva);

    private sealed record SelectedFunctions(
        LocatedFunction Origin,
        LocatedFunction DeleteMessages,
        LocatedFunction AddMessageToDb,
        CallChainResult? DeleteMessagesChain,
        CallChainResult? AddMessageToDbChain);

    private static readonly string[] X64RegisterNames =
    {
        "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
        "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"
    };
}

internal sealed class FunctionCallScanner
{
    private readonly ConcurrentDictionary<uint, IReadOnlyList<CallInstruction>> _cache = new();
    private readonly ConcurrentDictionary<uint, IReadOnlyList<X64Instruction>> _instructionCache = new();
    private readonly X64Disassembler _disassembler;
    private readonly PeImage _image;
    private readonly PeSection _text;

    public FunctionCallScanner(PeImage image, PeSection text, X64Disassembler disassembler)
    {
        _image = image;
        _text = text;
        _disassembler = disassembler;
    }

    public IReadOnlyList<CallInstruction> GetCalls(uint functionRva)
    {
        return _cache.GetOrAdd(functionRva, ScanCalls);
    }

    public bool TryFindZeroArgumentSetupBeforeCall(
        uint callerFunctionRva,
        uint callRva,
        out X64Instruction evidence)
    {
        const uint maxLookback = 0x100;
        var minRva = callRva > maxLookback ? callRva - maxLookback : callerFunctionRva;
        if (minRva < callerFunctionRva)
        {
            minRva = callerFunctionRva;
        }

        var instructions = GetInstructions(callerFunctionRva);
        for (var index = instructions.Count - 1; index >= 0; index--)
        {
            var instruction = instructions[index];
            if (instruction.Rva >= callRva || instruction.Rva < minRva)
            {
                continue;
            }

            if (string.Equals(instruction.Mnemonic.Trim(), "call", StringComparison.OrdinalIgnoreCase))
            {
                break;
            }

            if (IsZeroArgumentSetup(instruction))
            {
                evidence = instruction;
                return true;
            }
        }

        return TryFindZeroArgumentSetupByOpcode(callerFunctionRva, callRva, minRva, out evidence);
    }

    private IReadOnlyList<X64Instruction> GetInstructions(uint functionRva)
    {
        return _instructionCache.GetOrAdd(functionRva, ScanInstructions);
    }

    private IReadOnlyList<X64Instruction> ScanInstructions(uint functionRva)
    {
        var function = _image.FindFunction(functionRva);
        if (function is null)
        {
            return Array.Empty<X64Instruction>();
        }

        var runtimeFunction = function.Value;
        var startOffset = (int)(runtimeFunction.BeginRva - _text.VirtualAddress);
        var length = (int)Math.Min(runtimeFunction.EndRva - runtimeFunction.BeginRva, _text.Bytes.Length - startOffset);
        if (startOffset < 0 || length <= 0 || startOffset >= _text.Bytes.Length)
        {
            return Array.Empty<X64Instruction>();
        }

        return _disassembler.Disassemble(_text.Bytes.Span, startOffset, length, runtimeFunction.BeginRva);
    }

    private IReadOnlyList<CallInstruction> ScanCalls(uint functionRva)
    {
        var function = _image.FindFunction(functionRva);
        if (function is null)
        {
            return Array.Empty<CallInstruction>();
        }

        var runtimeFunction = function.Value;
        var startOffset = (int)(runtimeFunction.BeginRva - _text.VirtualAddress);
        var length = (int)Math.Min(runtimeFunction.EndRva - runtimeFunction.BeginRva, _text.Bytes.Length - startOffset);
        if (startOffset < 0 || length <= 0 || startOffset >= _text.Bytes.Length)
        {
            return Array.Empty<CallInstruction>();
        }

        var disassembled = _disassembler.Disassemble(_text.Bytes.Span, startOffset, length, runtimeFunction.BeginRva);
        if (disassembled.Count > 0)
        {
            return disassembled
                .Where(instruction => instruction.Mnemonic == "call" && instruction.DirectTargetRva is not null)
                .Select(instruction => new CallInstruction(
                    instruction.Rva,
                    runtimeFunction.BeginRva,
                    _image.FindFunction(instruction.DirectTargetRva!.Value)?.BeginRva ?? instruction.DirectTargetRva.Value,
                    instruction.Text))
                .ToList();
        }

        return ScanCallsByOpcode(startOffset, length, runtimeFunction.BeginRva);
    }

    private IReadOnlyList<CallInstruction> ScanCallsByOpcode(int startOffset, int length, uint functionRva)
    {
        var calls = new List<CallInstruction>();
        var span = _text.Bytes.Span;
        var endOffset = startOffset + length - 5;
        for (var offset = startOffset; offset <= endOffset; offset++)
        {
            if (span[offset] != 0xE8)
            {
                continue;
            }

            var callRva = functionRva + (uint)(offset - startOffset);
            var rel = BinaryPrimitives.ReadInt32LittleEndian(span.Slice(offset + 1, 4));
            var targetRva = unchecked((uint)(callRva + 5 + rel));
            var targetFunction = _image.FindFunction(targetRva);
            if (targetFunction is null)
            {
                continue;
            }

            calls.Add(new CallInstruction(
                callRva,
                functionRva,
                targetFunction.Value.BeginRva,
                $"call {NumericParser.FormatHexUnchecked(targetRva)}"));
        }

        return calls;
    }

    private bool TryFindZeroArgumentSetupByOpcode(
        uint callerFunctionRva,
        uint callRva,
        uint minRva,
        out X64Instruction evidence)
    {
        evidence = default!;
        var startOffset = (int)(minRva - _text.VirtualAddress);
        var endOffset = (int)(callRva - _text.VirtualAddress);
        if (startOffset < 0 || endOffset <= startOffset || startOffset >= _text.Bytes.Length)
        {
            return false;
        }

        endOffset = Math.Min(endOffset, _text.Bytes.Length);
        var span = _text.Bytes.Span;
        for (var offset = endOffset - 1; offset >= startOffset; offset--)
        {
            if (span[offset] == 0xE8)
            {
                break;
            }

            if (TryMatchZeroArgumentOpcode(span, offset, endOffset, out var text))
            {
                var rva = _text.VirtualAddress + (uint)offset;
                evidence = new X64Instruction(rva, "zero", text);
                return true;
            }
        }

        return false;
    }

    private static bool TryMatchZeroArgumentOpcode(ReadOnlySpan<byte> bytes, int offset, int endOffset, out string text)
    {
        text = string.Empty;
        if (offset + 2 <= endOffset)
        {
            var b0 = bytes[offset];
            var b1 = bytes[offset + 1];
            if ((b0 is 0x31 or 0x33 or 0x29 or 0x2B) && b1 is 0xC9 or 0xD2)
            {
                text = b1 == 0xC9 ? "xor/sub ecx, ecx" : "xor/sub edx, edx";
                return true;
            }
        }

        if (offset + 3 <= endOffset)
        {
            var b0 = bytes[offset];
            var b1 = bytes[offset + 1];
            var b2 = bytes[offset + 2];
            if (b0 is 0x45 or 0x4D && b1 is 0x31 or 0x33 or 0x29 or 0x2B && b2 is 0xC0 or 0xC9)
            {
                text = b2 == 0xC0 ? "xor/sub r8d, r8d" : "xor/sub r9d, r9d";
                return true;
            }

            if (b0 == 0x41 && b2 == 0x00 && b1 is 0xB0 or 0xB1)
            {
                text = b1 == 0xB0 ? "mov r8b, 0" : "mov r9b, 0";
                return true;
            }

            if (b2 == 0x00 && b0 is 0xB1 or 0xB2)
            {
                text = b0 == 0xB1 ? "mov cl, 0" : "mov dl, 0";
                return true;
            }
        }

        if (offset + 5 <= endOffset && bytes.Slice(offset + 1, 4).SequenceEqual(stackalloc byte[] { 0, 0, 0, 0 }))
        {
            if (bytes[offset] is 0xB9 or 0xBA)
            {
                text = bytes[offset] == 0xB9 ? "mov ecx, 0" : "mov edx, 0";
                return true;
            }
        }

        if (offset + 6 <= endOffset &&
            bytes[offset] == 0x41 &&
            bytes[offset + 1] is 0xB8 or 0xB9 &&
            bytes.Slice(offset + 2, 4).SequenceEqual(stackalloc byte[] { 0, 0, 0, 0 }))
        {
            text = bytes[offset + 1] == 0xB8 ? "mov r8d, 0" : "mov r9d, 0";
            return true;
        }

        if (offset + 8 <= endOffset &&
            bytes[offset] == 0xC7 &&
            bytes[offset + 1] == 0x44 &&
            bytes[offset + 2] == 0x24 &&
            bytes.Slice(offset + 4, 4).SequenceEqual(stackalloc byte[] { 0, 0, 0, 0 }))
        {
            text = "mov dword ptr [rsp+disp], 0";
            return true;
        }

        if (offset + 9 <= endOffset &&
            bytes[offset] == 0x48 &&
            bytes[offset + 1] == 0xC7 &&
            bytes[offset + 2] == 0x44 &&
            bytes[offset + 3] == 0x24 &&
            bytes.Slice(offset + 5, 4).SequenceEqual(stackalloc byte[] { 0, 0, 0, 0 }))
        {
            text = "mov qword ptr [rsp+disp], 0";
            return true;
        }

        return false;
    }

    private static bool IsZeroArgumentSetup(X64Instruction instruction)
    {
        var mnemonic = instruction.Mnemonic.Trim().ToLowerInvariant();
        var operands = instruction.Operands;
        if (operands.Length == 0)
        {
            return false;
        }

        if ((mnemonic is "xor" or "sub") &&
            operands.Length >= 2 &&
            IsArgumentRegister(operands[0]) &&
            NormalizeOperand(operands[0]) == NormalizeOperand(operands[1]))
        {
            return true;
        }

        if ((mnemonic is "mov" or "movabs" or "and") &&
            operands.Length >= 2 &&
            (IsArgumentRegister(operands[0]) || IsStackArgumentOperand(operands[0])) &&
            IsZeroImmediate(operands[1]))
        {
            return true;
        }

        if (mnemonic == "push" && operands.Length >= 1 && IsZeroImmediate(operands[0]))
        {
            return true;
        }

        return false;
    }

    private static bool IsArgumentRegister(string operand)
    {
        return NormalizeOperand(operand) is
            "rcx" or "ecx" or "cx" or "cl" or
            "rdx" or "edx" or "dx" or "dl" or
            "r8" or "r8d" or "r8w" or "r8b" or
            "r9" or "r9d" or "r9w" or "r9b";
    }

    private static bool IsStackArgumentOperand(string operand)
    {
        var value = NormalizeOperand(operand);
        return value.Contains("[rsp");
    }

    private static bool IsZeroImmediate(string operand)
    {
        var value = NormalizeOperand(operand);
        if (value == "0" || value == "0x0")
        {
            return true;
        }

        return value.StartsWith("0x", StringComparison.Ordinal) &&
               ulong.TryParse(value[2..], NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var hex) &&
               hex == 0;
    }

    private static string NormalizeOperand(string operand)
    {
        return operand
            .Trim()
            .ToLowerInvariant()
            .Replace(" ", string.Empty)
            .Replace("byteptr", string.Empty)
            .Replace("wordptr", string.Empty)
            .Replace("dwordptr", string.Empty)
            .Replace("qwordptr", string.Empty);
    }
}

internal sealed class PeImage
{
    private readonly List<RuntimeFunction> _runtimeFunctions;

    private PeImage(byte[] fileBytes, IReadOnlyList<PeSection> sections, List<RuntimeFunction> runtimeFunctions)
    {
        FileBytes = fileBytes;
        Sections = sections;
        _runtimeFunctions = runtimeFunctions;
    }

    public byte[] FileBytes { get; }

    public IReadOnlyList<PeSection> Sections { get; }

    public static PeImage Load(string path)
    {
        var fileBytes = File.ReadAllBytes(path);
        using var stream = new MemoryStream(fileBytes, writable: false);
        using var reader = new PEReader(stream);
        var sections = reader.PEHeaders.SectionHeaders
            .Select(section => PeSection.Create(fileBytes, section))
            .ToList();

        var image = new PeImage(fileBytes, sections, new List<RuntimeFunction>());
        image._runtimeFunctions.AddRange(image.LoadRuntimeFunctions(reader.PEHeaders.PEHeader?.ExceptionTableDirectory));
        return image;
    }

    public PeSection GetRequiredSection(string name)
    {
        return Sections.FirstOrDefault(section => section.Name == name)
               ?? throw new InvalidDataException($"未找到 {name} 节。");
    }

    public RuntimeFunction? FindFunction(uint rva)
    {
        var left = 0;
        var right = _runtimeFunctions.Count - 1;
        while (left <= right)
        {
            var middle = left + ((right - left) / 2);
            var function = _runtimeFunctions[middle];
            if (rva < function.BeginRva)
            {
                right = middle - 1;
                continue;
            }

            if (rva >= function.EndRva)
            {
                left = middle + 1;
                continue;
            }

            return function;
        }

        return null;
    }

    private IReadOnlyList<RuntimeFunction> LoadRuntimeFunctions(DirectoryEntry? exceptionDirectory)
    {
        if (exceptionDirectory is null ||
            exceptionDirectory.Value.RelativeVirtualAddress == 0 ||
            exceptionDirectory.Value.Size < 12)
        {
            return Array.Empty<RuntimeFunction>();
        }

        var offset = RvaToOffset((uint)exceptionDirectory.Value.RelativeVirtualAddress);
        if (offset is null)
        {
            return Array.Empty<RuntimeFunction>();
        }

        var count = exceptionDirectory.Value.Size / 12;
        var functions = new List<RuntimeFunction>(count);
        for (var index = 0; index < count; index++)
        {
            var entryOffset = offset.Value + (index * 12);
            if (entryOffset < 0 || entryOffset + 12 > FileBytes.Length)
            {
                break;
            }

            var begin = BinaryPrimitives.ReadUInt32LittleEndian(FileBytes.AsSpan(entryOffset, 4));
            var end = BinaryPrimitives.ReadUInt32LittleEndian(FileBytes.AsSpan(entryOffset + 4, 4));
            if (begin != 0 && end > begin)
            {
                functions.Add(new RuntimeFunction(begin, end));
            }
        }

        return functions
            .Distinct()
            .OrderBy(function => function.BeginRva)
            .ToList();
    }

    private int? RvaToOffset(uint rva)
    {
        foreach (var section in Sections)
        {
            var sectionSize = Math.Max(section.VirtualSize, section.RawSize);
            if (rva >= section.VirtualAddress && rva < section.VirtualAddress + sectionSize)
            {
                return checked((int)(section.RawPointer + (rva - section.VirtualAddress)));
            }
        }

        return null;
    }
}

internal sealed record PeSection(
    string Name,
    uint VirtualAddress,
    uint VirtualSize,
    uint RawPointer,
    uint RawSize,
    ReadOnlyMemory<byte> Bytes)
{
    public static PeSection Create(byte[] fileBytes, SectionHeader header)
    {
        var rawPointer = checked((uint)Math.Max(header.PointerToRawData, 0));
        var rawSize = checked((uint)Math.Max(header.SizeOfRawData, 0));
        var available = rawPointer < fileBytes.Length ? fileBytes.Length - (int)rawPointer : 0;
        var length = Math.Min((int)rawSize, available);
        return new PeSection(
            header.Name,
            checked((uint)header.VirtualAddress),
            checked((uint)header.VirtualSize),
            rawPointer,
            rawSize,
            new ReadOnlyMemory<byte>(fileBytes, (int)rawPointer, length));
    }
}

internal readonly record struct RuntimeFunction(uint BeginRva, uint EndRva);

internal sealed record X64Instruction(uint Rva, string Mnemonic, string OperandText)
{
    public string Text => string.IsNullOrWhiteSpace(OperandText) ? Mnemonic : $"{Mnemonic} {OperandText}";

    public string[] Operands => OperandText.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);

    public uint? DirectTargetRva => TryParseDirectTarget(OperandText);

    private static uint? TryParseDirectTarget(string operandText)
    {
        var operand = operandText.Trim();
        if (!operand.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        var end = operand.IndexOfAny(new[] { ' ', ',', ';' });
        var hex = end >= 0 ? operand[..end] : operand;
        return uint.TryParse(hex[2..], NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var value)
            ? value
            : null;
    }
}

internal sealed class X64Disassembler : IDisposable
{
    private readonly NativeCapstoneDisassembler? _native;

    private X64Disassembler(NativeCapstoneDisassembler? native)
    {
        _native = native;
    }

    public bool UsedNativeCapstone => _native is not null;

    public static X64Disassembler Create()
    {
        return new X64Disassembler(NativeCapstoneDisassembler.TryCreate());
    }

    public IReadOnlyList<X64Instruction> Disassemble(ReadOnlySpan<byte> bytes, int offset, int length, uint rva)
    {
        if (_native is null)
        {
            return Array.Empty<X64Instruction>();
        }

        return _native.Disassemble(bytes.Slice(offset, length), rva);
    }

    public string? DisassembleOne(ReadOnlySpan<byte> bytes, int offset, uint rva, int maxLength)
    {
        if (_native is null)
        {
            return null;
        }

        var length = Math.Min(maxLength, bytes.Length - offset);
        return _native.Disassemble(bytes.Slice(offset, length), rva).FirstOrDefault()?.Text;
    }

    public void Dispose()
    {
        _native?.Dispose();
    }
}

internal sealed class NativeCapstoneDisassembler : IDisposable
{
    private const int CsArchX86 = 3;
    private const int CsMode64 = 1 << 3;
    private readonly IntPtr _handle;

    private NativeCapstoneDisassembler(IntPtr handle)
    {
        _handle = handle;
    }

    public static NativeCapstoneDisassembler? TryCreate()
    {
        try
        {
            if (CsOpen(CsArchX86, CsMode64, out var handle) != 0 || handle == IntPtr.Zero)
            {
                return null;
            }

            return new NativeCapstoneDisassembler(handle);
        }
        catch (DllNotFoundException)
        {
            return null;
        }
        catch (EntryPointNotFoundException)
        {
            return null;
        }
        catch (BadImageFormatException)
        {
            return null;
        }
    }

    public IReadOnlyList<X64Instruction> Disassemble(ReadOnlySpan<byte> code, uint rva)
    {
        if (code.IsEmpty)
        {
            return Array.Empty<X64Instruction>();
        }

        var buffer = code.ToArray();
        var count = CsDisasm(_handle, buffer, (UIntPtr)buffer.Length, rva, UIntPtr.Zero, out var instructionPointer);
        if (count == UIntPtr.Zero || instructionPointer == IntPtr.Zero)
        {
            return Array.Empty<X64Instruction>();
        }

        try
        {
            var instructionCount = checked((int)count);
            var instructionSize = Marshal.SizeOf<CsInsn>();
            var result = new List<X64Instruction>(instructionCount);
            for (var index = 0; index < instructionCount; index++)
            {
                var itemPointer = IntPtr.Add(instructionPointer, index * instructionSize);
                var item = Marshal.PtrToStructure<CsInsn>(itemPointer);
                result.Add(new X64Instruction(
                    checked((uint)item.Address),
                    item.Mnemonic.TrimEnd('\0'),
                    item.OperandText.TrimEnd('\0')));
            }

            return result;
        }
        finally
        {
            CsFree(instructionPointer, count);
        }
    }

    public void Dispose()
    {
        var handle = _handle;
        if (handle != IntPtr.Zero)
        {
            CsClose(ref handle);
        }
    }

    [DllImport("capstone", CallingConvention = CallingConvention.Cdecl, EntryPoint = "cs_open")]
    private static extern int CsOpen(int arch, int mode, out IntPtr handle);

    [DllImport("capstone", CallingConvention = CallingConvention.Cdecl, EntryPoint = "cs_disasm")]
    private static extern UIntPtr CsDisasm(
        IntPtr handle,
        byte[] code,
        UIntPtr codeSize,
        ulong address,
        UIntPtr count,
        out IntPtr instruction);

    [DllImport("capstone", CallingConvention = CallingConvention.Cdecl, EntryPoint = "cs_free")]
    private static extern void CsFree(IntPtr instruction, UIntPtr count);

    [DllImport("capstone", CallingConvention = CallingConvention.Cdecl, EntryPoint = "cs_close")]
    private static extern int CsClose(ref IntPtr handle);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
    private struct CsInsn
    {
        public uint Id;

        public ulong Address;

        public ushort Size;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] Bytes;

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 32)]
        public string Mnemonic;

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 160)]
        public string OperandText;

        public IntPtr Detail;
    }
}

internal static class EnumerableExtensions
{
    public static uint? FirstOrDefaultValue(this IOrderedEnumerable<uint> values)
    {
        foreach (var value in values)
        {
            return value;
        }

        return null;
    }
}
