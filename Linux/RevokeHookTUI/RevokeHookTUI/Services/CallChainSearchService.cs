using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Reflection.PortableExecutable;
using System.Runtime.InteropServices;
using System.Text;

namespace RevokeHookTUI.Services;

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
        string executablePath,
        CallChainSearchRequest request,
        IProgress<CallChainSearchProgress>? progress = null)
    {
        if (!File.Exists(executablePath))
        {
            throw new FileNotFoundException("目标文件不存在。", executablePath);
        }

        var reporter = new SearchProgressReporter(progress);

        reporter.Report(5, "读取可执行文件...", true);
        var image = ExecutableImage.Load(executablePath);
        var text = image.GetRequiredSection(".text");
        var stringSectionName = image.IsElf ? ".rodata" : ".rdata";
        var stringSection = image.GetRequiredSection(stringSectionName);
        reporter.Report(
            8,
            $"已识别 {(image.IsElf ? "ELF" : "PE")} 文件, .text={text.Bytes.Length / 1024d:F1}KB, {stringSectionName}={stringSection.Bytes.Length / 1024d:F1}KB, 函数边界={image.RuntimeFunctions.Count}({image.FunctionBoundarySource}), call入口={image.DirectCallTargetCount}",
            true);

        reporter.Report(15, "解析三个加密字符串的 16 进制值...", true);
        var signatures = new[]
        {
            new SignatureTarget("CoReplaceOriginMessageByRevoke", ParseHexBytes(request.Signature1Hex)),
            new SignatureTarget("DeleteMessages", ParseHexBytes(request.Signature2Hex)),
            new SignatureTarget("CoAddMessageToDB", ParseHexBytes(request.Signature3Hex))
        };

        reporter.Report(25, $"在 {stringSectionName} 并行定位字符串...", true);
        var stringMatches = LocateStringMatches(stringSection, signatures, stringSectionName, reporter);

        reporter.Report(45, "在 .text 并行定位 lea 引用...", true);
        using var disassembler = X64Disassembler.Create();
        reporter.Report(
            48,
            disassembler.UsedNativeCapstone ? "已加载 libcapstone, 使用原生反汇编辅助解析。" : "未加载 libcapstone, 使用内置 lea/call 降级解析。",
            true);
        var functionCandidates = LocateFunctionCandidatesFromLea(image, text, stringMatches, disassembler, reporter);

        reporter.Report(65, "解析调用图并搜索三层调用链...", true);
        var callScanner = new FunctionCallScanner(image, text, disassembler);
        var selected = SelectFunctionsByCallChains(callScanner, functionCandidates, reporter);

        reporter.Report(100, "搜索完成。", true);
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
        PeSection stringSection,
        IReadOnlyList<SignatureTarget> signatures,
        string sectionName,
        SearchProgressReporter progress)
    {
        var results = new ConcurrentDictionary<string, List<StringMatch>>();

        Parallel.ForEach(signatures, signature =>
        {
            var matches = ParallelSearch(stringSection.Bytes, signature.Bytes);
            if (matches.Count == 0)
            {
                throw new InvalidOperationException($"未在 {sectionName} 找到 {signature.Name} 的字符串特征。");
            }

            results[signature.Name] = matches
                .Select(offset => new StringMatch(
                    checked(stringSection.RawPointer + (uint)offset),
                    checked(stringSection.VirtualAddress + (uint)offset)))
                .ToList();
            progress.Report(35, $"{sectionName} 已定位 {signature.Name}: {matches.Count} 个字符串匹配");
        });

        return results.ToDictionary(pair => pair.Key, pair => pair.Value, StringComparer.Ordinal);
    }

    private static Dictionary<string, List<LocatedFunction>> LocateFunctionCandidatesFromLea(
        ExecutableImage image,
        PeSection text,
        IReadOnlyDictionary<string, List<StringMatch>> stringMatches,
        X64Disassembler disassembler,
        SearchProgressReporter progress)
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
            progress.Report(58, $".text 已定位 {pair.Key}: {candidates.Count} 个候选函数");
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
        IReadOnlyDictionary<string, List<LocatedFunction>> candidates,
        SearchProgressReporter progress)
    {
        var origins = candidates["CoReplaceOriginMessageByRevoke"];
        var deleteMessagesCandidates = candidates["DeleteMessages"];
        var addMessageToDbCandidates = candidates["CoAddMessageToDB"];
        var totalAttempts = Math.Max(1, origins.Count * deleteMessagesCandidates.Count * addMessageToDbCandidates.Count);
        var attempt = 0;

        progress.Report(
            66,
            $"调用链候选组合: origin={origins.Count}, delmsg={deleteMessagesCandidates.Count}, add2db={addMessageToDbCandidates.Count}, total={totalAttempts}",
            true);

        SelectedFunctions? bestPartial = null;
        for (var originIndex = 0; originIndex < origins.Count; originIndex++)
        {
            var origin = origins[originIndex];
            for (var deleteIndex = 0; deleteIndex < deleteMessagesCandidates.Count; deleteIndex++)
            {
                var deleteMessages = deleteMessagesCandidates[deleteIndex];
                progress.Report(
                    68,
                    $"搜索 DeleteMessages 链: origin {originIndex + 1}/{origins.Count} {NumericParser.FormatHexUnchecked(origin.FunctionRva)}, delete {deleteIndex + 1}/{deleteMessagesCandidates.Count} {NumericParser.FormatHexUnchecked(deleteMessages.FunctionRva)}",
                    true);

                var deleteChain = FindDeleteChainWithZeroArgumentSetup(
                    scanner,
                    origin.FunctionRva,
                    deleteMessages.FunctionRva);
                progress.Report(
                    73,
                    deleteChain is null
                        ? "DeleteMessages 链未命中, 继续尝试下一组候选。"
                        : $"DeleteMessages 链命中: root={NumericParser.FormatHexUnchecked(deleteChain.RootCallRva)}",
                    true);

                for (var addIndex = 0; addIndex < addMessageToDbCandidates.Count; addIndex++)
                {
                    attempt++;
                    var addMessageToDb = addMessageToDbCandidates[addIndex];
                    var percent = 74 + (int)(20d * attempt / totalAttempts);
                    progress.Report(
                        percent,
                        $"搜索 CoAddMessageToDB 链: 组合 {attempt}/{totalAttempts}, add2db {addIndex + 1}/{addMessageToDbCandidates.Count} {NumericParser.FormatHexUnchecked(addMessageToDb.FunctionRva)}",
                        true);

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
                        progress.Report(96, "DeleteMessages 与 CoAddMessageToDB 调用链均已命中。", true);
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

internal sealed class SearchProgressReporter
{
    private readonly IProgress<CallChainSearchProgress>? _progress;
    private readonly Stopwatch _stopwatch = Stopwatch.StartNew();
    private readonly object _syncRoot = new();
    private long _lastReportMilliseconds = -10_000;
    private string _lastMessage = string.Empty;

    public SearchProgressReporter(IProgress<CallChainSearchProgress>? progress)
    {
        _progress = progress;
    }

    public void Report(int percent, string message, bool force = false)
    {
        if (_progress is null)
        {
            return;
        }

        lock (_syncRoot)
        {
            var elapsedMilliseconds = _stopwatch.ElapsedMilliseconds;
            if (!force &&
                string.Equals(_lastMessage, message, StringComparison.Ordinal) &&
                elapsedMilliseconds - _lastReportMilliseconds < 1000)
            {
                return;
            }

            if (!force && elapsedMilliseconds - _lastReportMilliseconds < 650)
            {
                return;
            }

            _lastMessage = message;
            _lastReportMilliseconds = elapsedMilliseconds;
        }

        _progress.Report(new CallChainSearchProgress(Math.Clamp(percent, 0, 100), message));
    }
}

internal sealed class FunctionCallScanner
{
    private readonly ConcurrentDictionary<uint, IReadOnlyList<CallInstruction>> _cache = new();
    private readonly ConcurrentDictionary<uint, IReadOnlyList<X64Instruction>> _instructionCache = new();
    private readonly X64Disassembler _disassembler;
    private readonly ExecutableImage _image;
    private readonly PeSection _text;
    public FunctionCallScanner(
        ExecutableImage image,
        PeSection text,
        X64Disassembler disassembler)
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
            if ((b0 is 0x31 or 0x33 or 0x29 or 0x2B) && b1 is 0xC9 or 0xD2 or 0xFF or 0xF6)
            {
                text = b1 switch
                {
                    0xC9 => "xor/sub ecx, ecx",
                    0xD2 => "xor/sub edx, edx",
                    0xFF => "xor/sub edi, edi",
                    _ => "xor/sub esi, esi"
                };
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

            if (b2 == 0x00 && b0 is 0xB1 or 0xB2 or 0xB7 or 0xB6)
            {
                text = b0 switch
                {
                    0xB1 => "mov cl, 0",
                    0xB2 => "mov dl, 0",
                    0xB7 => "mov dil, 0",
                    _ => "mov sil, 0"
                };
                return true;
            }
        }

        if (offset + 5 <= endOffset && bytes.Slice(offset + 1, 4).SequenceEqual(stackalloc byte[] { 0, 0, 0, 0 }))
        {
            if (bytes[offset] is 0xB9 or 0xBA or 0xBF or 0xBE)
            {
                text = bytes[offset] switch
                {
                    0xB9 => "mov ecx, 0",
                    0xBA => "mov edx, 0",
                    0xBF => "mov edi, 0",
                    _ => "mov esi, 0"
                };
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
            "rdi" or "edi" or "di" or "dil" or
            "rsi" or "esi" or "si" or "sil" or
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

internal abstract class ExecutableImage
{
    private const int MaxHeuristicFunctionBytes = 0x80000;
    private readonly IReadOnlyList<uint> _directCallTargetRvas;
    private readonly IReadOnlyList<uint> _prologueRvas;

    protected ExecutableImage(
        byte[] fileBytes,
        IReadOnlyList<PeSection> sections,
        IReadOnlyList<RuntimeFunction> functions,
        bool isElf,
        string functionBoundarySource)
    {
        FileBytes = fileBytes;
        Sections = sections;
        IsElf = isElf;
        FunctionBoundarySource = functionBoundarySource;
        _directCallTargetRvas = BuildDirectCallTargetIndex();
        _prologueRvas = BuildPrologueIndex();
        RuntimeFunctions = NormalizeRuntimeFunctions(functions, sections, isElf, _directCallTargetRvas);
    }

    public byte[] FileBytes { get; }

    public IReadOnlyList<PeSection> Sections { get; }

    public IReadOnlyList<RuntimeFunction> RuntimeFunctions { get; }

    public bool IsElf { get; }

    public string FunctionBoundarySource { get; }

    public int DirectCallTargetCount => _directCallTargetRvas.Count;

    private static IReadOnlyList<RuntimeFunction> NormalizeRuntimeFunctions(
        IReadOnlyList<RuntimeFunction> functions,
        IReadOnlyList<PeSection> sections,
        bool isElf,
        IReadOnlyList<uint> directCallTargetRvas)
    {
        var text = sections.FirstOrDefault(section => section.Name == ".text");
        var ordered = functions
            .Where(function => function.EndRva > function.BeginRva)
            .Distinct()
            .OrderBy(function => function.BeginRva)
            .ThenByDescending(function => function.EndRva)
            .ToList();
        if (ordered.Count == 0)
        {
            return ordered;
        }

        var normalized = new List<RuntimeFunction>();
        foreach (var function in ordered)
        {
            if (normalized.Count == 0)
            {
                normalized.Add(function);
                continue;
            }

            var previous = normalized[^1];
            if (function.BeginRva < previous.EndRva ||
                ShouldMergeContiguousElfRange(text, isElf, directCallTargetRvas, previous, function))
            {
                if (function.EndRva > previous.EndRva)
                {
                    normalized[^1] = previous with { EndRva = function.EndRva };
                }

                continue;
            }

            normalized.Add(function);
        }

        return normalized;
    }

    private static bool ShouldMergeContiguousElfRange(
        PeSection? text,
        bool isElf,
        IReadOnlyList<uint> directCallTargetRvas,
        RuntimeFunction previous,
        RuntimeFunction current)
    {
        if (!isElf || text is null || current.BeginRva < previous.EndRva)
        {
            return false;
        }

        var gap = current.BeginRva - previous.EndRva;
        if (gap > 0x4000)
        {
            return false;
        }

        return !LooksLikeFunctionStartAtRva(text, current.BeginRva);
    }

    public static ExecutableImage Load(string path)
    {
        var fileBytes = File.ReadAllBytes(path);
        if (fileBytes.Length < 4)
        {
            throw new InvalidDataException("目标文件太小, 不是有效的 ELF/PE 二进制文件。请确认选择的是 Linux 微信真实可执行文件或 .so, 而不是启动脚本/快捷方式。");
        }

        if (fileBytes.Length >= 4 &&
            fileBytes[0] == 0x7F &&
            fileBytes[1] == (byte)'E' &&
            fileBytes[2] == (byte)'L' &&
            fileBytes[3] == (byte)'F')
        {
            return ElfImage.Load(fileBytes);
        }

        if (fileBytes.Length < 2 || fileBytes[0] != (byte)'M' || fileBytes[1] != (byte)'Z')
        {
            throw new InvalidDataException("目标文件不是 ELF 或 PE 二进制文件。请确认选择的是 Linux 微信真实可执行文件或 .so, 而不是启动脚本/快捷方式。");
        }

        return PeImage.Load(fileBytes);
    }

    public PeSection GetRequiredSection(string name)
    {
        return Sections.FirstOrDefault(section => section.Name == name)
               ?? throw new InvalidDataException($"未找到 {name} 节。");
    }

    public virtual RuntimeFunction? FindFunction(uint rva)
    {
        var text = Sections.FirstOrDefault(section => section.Name == ".text");
        if (text is null || rva < text.VirtualAddress || rva >= text.VirtualAddress + text.VirtualSize)
        {
            return null;
        }

        var found = FindFunctionInTable(rva);
        var exactCallTargetFunction = FindFunctionByExactCallTarget(text, rva, found);
        if (exactCallTargetFunction is not null)
        {
            return exactCallTargetFunction;
        }

        var refined = RefineFunctionByPrologue(text, rva, found);
        if (refined is not null)
        {
            return refined;
        }

        if (found is not null)
        {
            return found;
        }

        return FindFunctionByCallTargets(text, rva) ?? FindFunctionByPrologue(text, rva);
    }

    protected int? RvaToOffset(uint rva)
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

    private RuntimeFunction? FindFunctionInTable(uint rva)
    {
        var left = 0;
        var right = RuntimeFunctions.Count - 1;
        while (left <= right)
        {
            var middle = left + ((right - left) / 2);
            var function = RuntimeFunctions[middle];
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

    private IReadOnlyList<uint> BuildDirectCallTargetIndex()
    {
        var text = Sections.FirstOrDefault(section => section.Name == ".text");
        if (text is null || text.Bytes.Length < 5)
        {
            return Array.Empty<uint>();
        }

        var bytes = text.Bytes.Span;
        var targets = new HashSet<uint>();
        for (var offset = 0; offset <= bytes.Length - 5; offset++)
        {
            if (bytes[offset] != 0xE8)
            {
                continue;
            }

            var callRva = text.VirtualAddress + (uint)offset;
            var rel = BinaryPrimitives.ReadInt32LittleEndian(bytes.Slice(offset + 1, 4));
            var targetRva = unchecked((uint)(callRva + 5 + rel));
            if (targetRva >= text.VirtualAddress && targetRva < text.VirtualAddress + text.Bytes.Length)
            {
                targets.Add(targetRva);
            }
        }

        return targets.OrderBy(value => value).ToList();
    }

    private RuntimeFunction? FindFunctionByCallTargets(PeSection text, uint rva)
    {
        if (_directCallTargetRvas.Count == 0)
        {
            return null;
        }

        var begin = FindNearestCallTargetAtOrBefore(rva);
        if (begin is null || begin.Value < text.VirtualAddress)
        {
            return null;
        }

        var next = FindNearestCallTargetAfter(begin.Value);
        var textEnd = checked(text.VirtualAddress + (uint)text.Bytes.Length);
        var cappedEnd = begin.Value + MaxHeuristicFunctionBytes;
        var end = Math.Min(next ?? textEnd, Math.Min(textEnd, cappedEnd));
        if (end <= begin.Value || rva >= end)
        {
            return null;
        }

        return new RuntimeFunction(begin.Value, end);
    }

    private IReadOnlyList<uint> BuildPrologueIndex()
    {
        var text = Sections.FirstOrDefault(section => section.Name == ".text");
        if (text is null)
        {
            return Array.Empty<uint>();
        }

        var bytes = text.Bytes.Span;
        var starts = new List<uint>();
        for (var offset = 0; offset < bytes.Length; offset++)
        {
            if (LooksLikeFunctionStart(bytes, offset))
            {
                starts.Add(text.VirtualAddress + (uint)offset);
            }
        }

        return NormalizePrologueStarts(starts, text);
    }

    private static IReadOnlyList<uint> NormalizePrologueStarts(IReadOnlyList<uint> starts, PeSection text)
    {
        if (starts.Count <= 1)
        {
            return starts;
        }

        var normalized = new List<uint>();
        foreach (var start in starts.OrderBy(value => value))
        {
            if (normalized.Count > 0 &&
                start - normalized[^1] <= 32 &&
                IsInsideSamePrologue(text, normalized[^1], start))
            {
                continue;
            }

            normalized.Add(start);
        }

        return normalized;
    }

    private static bool IsInsideSamePrologue(PeSection text, uint firstRva, uint candidateRva)
    {
        if (firstRva < text.VirtualAddress ||
            candidateRva <= firstRva ||
            candidateRva >= text.VirtualAddress + text.Bytes.Length)
        {
            return false;
        }

        var firstOffset = checked((int)(firstRva - text.VirtualAddress));
        var candidateOffset = checked((int)(candidateRva - text.VirtualAddress));
        var bytes = text.Bytes.Span;
        var current = firstOffset;
        var sawPush = false;

        while (current < candidateOffset)
        {
            if (bytes[current] is 0x55 or 0x53 or 0x56 or 0x57)
            {
                current++;
                sawPush = true;
                continue;
            }

            if (current + 1 < bytes.Length && bytes[current] == 0x41 && bytes[current + 1] is >= 0x54 and <= 0x57)
            {
                current += 2;
                sawPush = true;
                continue;
            }

            break;
        }

        if (!sawPush)
        {
            return false;
        }

        if (current == candidateOffset)
        {
            return true;
        }

        return current + 3 == candidateOffset &&
               current + 3 <= bytes.Length &&
               bytes[current] == 0x48 &&
               bytes[current + 1] == 0x89 &&
               bytes[current + 2] == 0xE5;
    }

    private RuntimeFunction? RefineFunctionByPrologue(PeSection text, uint rva, RuntimeFunction? tableFunction)
    {
        var begin = FindNearestPrologueAtOrBefore(rva);
        if (begin is null)
        {
            return null;
        }

        if (tableFunction is not null &&
            (begin.Value < tableFunction.Value.BeginRva || begin.Value >= tableFunction.Value.EndRva))
        {
            return null;
        }

        var textEnd = checked(text.VirtualAddress + (uint)text.Bytes.Length);
        var nextPrologue = FindNearestPrologueAfter(begin.Value);
        var tableEnd = tableFunction?.EndRva ?? textEnd;
        var cappedEnd = begin.Value + MaxHeuristicFunctionBytes;
        var end = Math.Min(nextPrologue ?? tableEnd, Math.Min(tableEnd, Math.Min(textEnd, cappedEnd)));
        if (end <= begin.Value || rva >= end)
        {
            return null;
        }

        return new RuntimeFunction(begin.Value, end);
    }

    private RuntimeFunction? FindFunctionByExactCallTarget(PeSection text, uint rva, RuntimeFunction? tableFunction)
    {
        if (BinarySearch(_directCallTargetRvas, rva) < 0 || LooksLikeFunctionStartAtRva(text, rva))
        {
            return null;
        }

        if (tableFunction is not null &&
            (rva < tableFunction.Value.BeginRva || rva >= tableFunction.Value.EndRva))
        {
            return null;
        }

        var textEnd = checked(text.VirtualAddress + (uint)text.Bytes.Length);
        var nextPrologue = FindNearestPrologueAfter(rva);
        var tableEnd = tableFunction?.EndRva ?? textEnd;
        var wrapperEnd = rva + 0x200;
        var end = Math.Min(nextPrologue ?? tableEnd, Math.Min(tableEnd, Math.Min(textEnd, wrapperEnd)));
        if (end <= rva)
        {
            return null;
        }

        return new RuntimeFunction(rva, end);
    }

    private uint? FindNearestPrologueAtOrBefore(uint rva)
    {
        var index = BinarySearch(_prologueRvas, rva);
        if (index >= 0)
        {
            return _prologueRvas[index];
        }

        index = ~index - 1;
        return index >= 0 ? _prologueRvas[index] : null;
    }

    private uint? FindNearestPrologueAfter(uint rva)
    {
        var index = BinarySearch(_prologueRvas, rva);
        if (index >= 0)
        {
            index++;
        }
        else
        {
            index = ~index;
        }

        return index < _prologueRvas.Count ? _prologueRvas[index] : null;
    }

    private uint? FindNearestCallTargetAtOrBefore(uint rva)
    {
        var index = BinarySearch(_directCallTargetRvas, rva);
        if (index >= 0)
        {
            return _directCallTargetRvas[index];
        }

        index = ~index - 1;
        return index >= 0 ? _directCallTargetRvas[index] : null;
    }

    private uint? FindNearestCallTargetAfter(uint rva)
    {
        var index = BinarySearch(_directCallTargetRvas, rva);
        if (index >= 0)
        {
            index++;
        }
        else
        {
            index = ~index;
        }

        return index < _directCallTargetRvas.Count ? _directCallTargetRvas[index] : null;
    }

    private static int BinarySearch(IReadOnlyList<uint> values, uint target)
    {
        var left = 0;
        var right = values.Count - 1;
        while (left <= right)
        {
            var middle = left + ((right - left) / 2);
            var value = values[middle];
            if (value == target)
            {
                return middle;
            }

            if (value < target)
            {
                left = middle + 1;
                continue;
            }

            right = middle - 1;
        }

        return ~left;
    }

    private static RuntimeFunction? FindFunctionByPrologue(PeSection text, uint rva)
    {
        var bytes = text.Bytes.Span;
        var targetOffset = checked((int)(rva - text.VirtualAddress));
        if (targetOffset < 0 || targetOffset >= bytes.Length)
        {
            return null;
        }

        var beginOffset = 0;
        for (var offset = targetOffset; offset >= 0; offset--)
        {
            if (LooksLikeFunctionStart(bytes, offset))
            {
                beginOffset = offset;
                break;
            }
        }

        var endOffset = Math.Min(bytes.Length, beginOffset + MaxHeuristicFunctionBytes);
        for (var offset = Math.Max(beginOffset + 1, targetOffset + 1); offset < bytes.Length; offset++)
        {
            if (LooksLikeFunctionStart(bytes, offset))
            {
                endOffset = offset;
                break;
            }
        }

        if (endOffset <= beginOffset)
        {
            return null;
        }

        return new RuntimeFunction(
            checked(text.VirtualAddress + (uint)beginOffset),
            checked(text.VirtualAddress + (uint)endOffset));
    }

    private static bool LooksLikeFunctionStart(ReadOnlySpan<byte> bytes, int offset)
    {
        if (offset < 0 || offset >= bytes.Length)
        {
            return false;
        }

        if (offset > 0 && bytes[offset - 1] == 0x41 && bytes[offset] is >= 0x54 and <= 0x57)
        {
            return false;
        }

        if (offset + 4 <= bytes.Length &&
            bytes[offset] == 0x55 &&
            bytes[offset + 1] == 0x48 &&
            bytes[offset + 2] == 0x89 &&
            bytes[offset + 3] == 0xE5)
        {
            return true;
        }

        if (offset + 4 <= bytes.Length &&
            bytes[offset] == 0xF3 &&
            bytes[offset + 1] == 0x0F &&
            bytes[offset + 2] == 0x1E &&
            bytes[offset + 3] == 0xFA)
        {
            return true;
        }

        if (bytes[offset] is 0x55 or 0x53 or 0x56 or 0x57 ||
            offset + 1 < bytes.Length && bytes[offset] == 0x41 && bytes[offset + 1] is >= 0x54 and <= 0x57)
        {
            return LooksLikeCalleeSavePrologue(bytes, offset);
        }

        if (offset + 4 <= bytes.Length &&
            bytes[offset] == 0x48 &&
            bytes[offset + 1] == 0x83 &&
            bytes[offset + 2] == 0xEC)
        {
            return true;
        }

        return offset + 7 <= bytes.Length &&
               bytes[offset] == 0x48 &&
               bytes[offset + 1] == 0x81 &&
               bytes[offset + 2] == 0xEC;
    }

    private static bool LooksLikeCalleeSavePrologue(ReadOnlySpan<byte> bytes, int offset)
    {
        var current = offset;
        var pushCount = 0;
        while (current < bytes.Length)
        {
            if (bytes[current] is 0x55 or 0x53 or 0x56 or 0x57)
            {
                current++;
                pushCount++;
                continue;
            }

            if (current + 1 < bytes.Length && bytes[current] == 0x41 && bytes[current + 1] is >= 0x54 and <= 0x57)
            {
                current += 2;
                pushCount++;
                continue;
            }

            break;
        }

        if (pushCount == 0)
        {
            return false;
        }

        if (current + 4 <= bytes.Length &&
            bytes[current] == 0x48 &&
            bytes[current + 1] == 0x89 &&
            bytes[current + 2] == 0xE5)
        {
            return true;
        }

        if (current + 4 <= bytes.Length &&
            bytes[current] == 0x48 &&
            bytes[current + 1] == 0x83 &&
            bytes[current + 2] == 0xEC)
        {
            return true;
        }

        return current + 7 <= bytes.Length &&
               bytes[current] == 0x48 &&
               bytes[current + 1] == 0x81 &&
               bytes[current + 2] == 0xEC;
    }

    private static bool LooksLikeFunctionStartAtRva(PeSection text, uint rva)
    {
        if (rva < text.VirtualAddress || rva >= text.VirtualAddress + text.Bytes.Length)
        {
            return false;
        }

        return LooksLikeFunctionStart(text.Bytes.Span, checked((int)(rva - text.VirtualAddress)));
    }
}

internal sealed class PeImage : ExecutableImage
{
    private PeImage(byte[] fileBytes, IReadOnlyList<PeSection> sections, IReadOnlyList<RuntimeFunction> runtimeFunctions)
        : base(fileBytes, sections, runtimeFunctions, false, ".pdata")
    {
    }

    public static PeImage Load(byte[] fileBytes)
    {
        using var stream = new MemoryStream(fileBytes, writable: false);
        using var reader = new PEReader(stream);
        var sections = reader.PEHeaders.SectionHeaders
            .Select(section => PeSection.Create(fileBytes, section))
            .ToList();

        var image = new PeImage(fileBytes, sections, new List<RuntimeFunction>());
        return new PeImage(fileBytes, sections, image.LoadRuntimeFunctions(reader.PEHeaders.PEHeader?.ExceptionTableDirectory));
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

}

internal sealed class ElfImage : ExecutableImage
{
    private const uint ShtSymtab = 2;
    private const uint ShtDynsym = 11;
    private const byte SttFunc = 2;

    private ElfImage(byte[] fileBytes, IReadOnlyList<PeSection> sections, IReadOnlyList<RuntimeFunction> functions, string functionBoundarySource)
        : base(fileBytes, sections, functions, true, functionBoundarySource)
    {
    }

    public static ElfImage Load(byte[] fileBytes)
    {
        if (fileBytes.Length < 0x40 || fileBytes[4] != 2 || fileBytes[5] != 1)
        {
            throw new InvalidDataException("仅支持 64 位小端 ELF 文件。");
        }

        var sectionHeaders = ReadSectionHeaders(fileBytes);
        var sectionNameHeader = sectionHeaders.SectionNameIndex < sectionHeaders.Headers.Count
            ? sectionHeaders.Headers[sectionHeaders.SectionNameIndex]
            : throw new InvalidDataException("ELF 节名表索引无效。");
        var sectionNames = SliceFile(fileBytes, sectionNameHeader.Offset, sectionNameHeader.Size);

        var sections = new List<PeSection>();
        foreach (var header in sectionHeaders.Headers)
        {
            var name = ReadString(sectionNames, header.NameOffset);
            if (string.IsNullOrWhiteSpace(name))
            {
                continue;
            }

            sections.Add(PeSection.Create(
                fileBytes,
                name,
                checked((uint)header.Address),
                checked((uint)header.Size),
                checked((uint)header.Offset),
                checked((uint)header.Size)));
        }

        var ehFrameFunctions = LoadEhFrameFunctions(fileBytes, sections);
        var functions = ehFrameFunctions.Count > 0
            ? ehFrameFunctions
            : LoadSymbolFunctions(fileBytes, sectionHeaders.Headers);
        var functionBoundarySource = ehFrameFunctions.Count > 0 ? ".eh_frame" : ".symtab/.dynsym";
        return new ElfImage(fileBytes, sections, functions, functionBoundarySource);
    }

    private static ElfSectionHeaderTable ReadSectionHeaders(byte[] fileBytes)
    {
        var sectionHeaderOffset = checked((long)BinaryPrimitives.ReadUInt64LittleEndian(fileBytes.AsSpan(0x28, 8)));
        var sectionHeaderSize = BinaryPrimitives.ReadUInt16LittleEndian(fileBytes.AsSpan(0x3A, 2));
        var sectionHeaderCount = BinaryPrimitives.ReadUInt16LittleEndian(fileBytes.AsSpan(0x3C, 2));
        var sectionNameIndex = BinaryPrimitives.ReadUInt16LittleEndian(fileBytes.AsSpan(0x3E, 2));

        if (sectionHeaderSize < 64 || sectionHeaderCount == 0)
        {
            throw new InvalidDataException("ELF 节表无效。");
        }

        var headers = new List<ElfSectionHeader>(sectionHeaderCount);
        for (var index = 0; index < sectionHeaderCount; index++)
        {
            var offset = checked(sectionHeaderOffset + (index * sectionHeaderSize));
            var span = fileBytes.AsSpan(checked((int)offset), sectionHeaderSize);
            headers.Add(new ElfSectionHeader(
                BinaryPrimitives.ReadUInt32LittleEndian(span.Slice(0, 4)),
                BinaryPrimitives.ReadUInt32LittleEndian(span.Slice(4, 4)),
                BinaryPrimitives.ReadUInt64LittleEndian(span.Slice(0x10, 8)),
                BinaryPrimitives.ReadUInt64LittleEndian(span.Slice(0x18, 8)),
                BinaryPrimitives.ReadUInt64LittleEndian(span.Slice(0x20, 8)),
                BinaryPrimitives.ReadUInt64LittleEndian(span.Slice(0x38, 8))));
        }

        return new ElfSectionHeaderTable(headers, sectionNameIndex);
    }

    private static IReadOnlyList<RuntimeFunction> LoadSymbolFunctions(byte[] fileBytes, IReadOnlyList<ElfSectionHeader> headers)
    {
        var functions = new List<RuntimeFunction>();
        foreach (var header in headers.Where(header => header.Type is ShtSymtab or ShtDynsym))
        {
            var entrySize = header.EntrySize == 0 ? 24 : checked((int)header.EntrySize);
            var table = SliceFile(fileBytes, header.Offset, header.Size);
            for (var offset = 0; offset + 24 <= table.Length; offset += entrySize)
            {
                var info = table[offset + 4];
                if ((info & 0x0F) != SttFunc)
                {
                    continue;
                }

                var value = BinaryPrimitives.ReadUInt64LittleEndian(table.Slice(offset + 8, 8));
                var size = BinaryPrimitives.ReadUInt64LittleEndian(table.Slice(offset + 16, 8));
                if (value == 0 || size == 0 || value > uint.MaxValue || value + size > uint.MaxValue)
                {
                    continue;
                }

                functions.Add(new RuntimeFunction(checked((uint)value), checked((uint)(value + size))));
            }
        }

        return functions
            .Distinct()
            .OrderBy(function => function.BeginRva)
            .ToList();
    }

    private static IReadOnlyList<RuntimeFunction> LoadEhFrameFunctions(byte[] fileBytes, IReadOnlyList<PeSection> sections)
    {
        var text = sections.FirstOrDefault(section => section.Name == ".text");
        var ehFrame = sections.FirstOrDefault(section => section.Name == ".eh_frame");
        var ehFrameHeader = sections.FirstOrDefault(section => section.Name == ".eh_frame_hdr");
        if (text is null || ehFrame is null || ehFrameHeader is null)
        {
            return Array.Empty<RuntimeFunction>();
        }

        var functions = new List<RuntimeFunction>();
        try
        {
            var headerReader = new DwarfEncodedReader(
                ehFrameHeader.Bytes.Span,
                ehFrameHeader.VirtualAddress,
                ehFrameHeader.VirtualAddress);
            if (!headerReader.TryReadByte(out var version) || version != 1 ||
                !headerReader.TryReadByte(out var ehFramePtrEncoding) ||
                !headerReader.TryReadByte(out var fdeCountEncoding) ||
                !headerReader.TryReadByte(out var tableEncoding))
            {
                return Array.Empty<RuntimeFunction>();
            }

            if (!headerReader.TryReadEncoded(ehFramePtrEncoding, out _) ||
                !headerReader.TryReadEncoded(fdeCountEncoding, out var fdeCountValue) ||
                fdeCountValue <= 0 ||
                fdeCountValue > int.MaxValue)
            {
                return Array.Empty<RuntimeFunction>();
            }

            var fdeCount = checked((int)fdeCountValue);
            for (var index = 0; index < fdeCount; index++)
            {
                if (!headerReader.TryReadEncoded(tableEncoding, out _) ||
                    !headerReader.TryReadEncoded(tableEncoding, out var fdeAddress))
                {
                    break;
                }

                if (fdeAddress < ehFrame.VirtualAddress ||
                    fdeAddress >= ehFrame.VirtualAddress + ehFrame.Bytes.Length)
                {
                    continue;
                }

                var fdeOffset = checked((int)(fdeAddress - ehFrame.VirtualAddress));
                if (TryReadEhFrameFde(ehFrame, text, fdeOffset, out var function))
                {
                    functions.Add(function);
                }
            }
        }
        catch
        {
            return Array.Empty<RuntimeFunction>();
        }

        return functions
            .Where(function => function.BeginRva >= text.VirtualAddress &&
                               function.EndRva > function.BeginRva &&
                               function.EndRva <= text.VirtualAddress + text.Bytes.Length)
            .Distinct()
            .OrderBy(function => function.BeginRva)
            .ToList();
    }

    private static bool TryReadEhFrameFde(PeSection ehFrame, PeSection text, int fdeOffset, out RuntimeFunction function)
    {
        function = default;
        var bytes = ehFrame.Bytes.Span;
        if (!TryReadFrameEntryHeader(bytes, fdeOffset, out var idOffset, out var contentOffset, out var entryEnd, out var is64BitLength) ||
            is64BitLength ||
            idOffset + 4 > bytes.Length)
        {
            return false;
        }

        var ciePointer = BinaryPrimitives.ReadUInt32LittleEndian(bytes.Slice(idOffset, 4));
        if (ciePointer == 0)
        {
            return false;
        }

        var cieOffset = checked(idOffset - (int)ciePointer);
        if (!TryReadCieFdePointerEncoding(ehFrame, cieOffset, out var fdePointerEncoding))
        {
            return false;
        }

        var reader = new DwarfEncodedReader(
            bytes.Slice(contentOffset, entryEnd - contentOffset),
            ehFrame.VirtualAddress + (uint)contentOffset,
            ehFrame.VirtualAddress);
        if (!reader.TryReadEncoded(fdePointerEncoding, out var beginValue) ||
            !reader.TryReadEncoded((byte)(fdePointerEncoding & 0x0F), out var rangeValue) ||
            beginValue <= 0 ||
            rangeValue <= 0 ||
            beginValue > uint.MaxValue ||
            beginValue + rangeValue > uint.MaxValue)
        {
            return false;
        }

        var begin = checked((uint)beginValue);
        var end = checked((uint)(beginValue + rangeValue));
        if (begin < text.VirtualAddress ||
            end <= begin ||
            end > text.VirtualAddress + text.Bytes.Length)
        {
            return false;
        }

        function = new RuntimeFunction(begin, end);
        return true;
    }

    private static bool TryReadCieFdePointerEncoding(PeSection ehFrame, int cieOffset, out byte pointerEncoding)
    {
        pointerEncoding = 0;
        var bytes = ehFrame.Bytes.Span;
        if (!TryReadFrameEntryHeader(bytes, cieOffset, out var idOffset, out var contentOffset, out var entryEnd, out var is64BitLength) ||
            is64BitLength ||
            idOffset + 4 > bytes.Length ||
            BinaryPrimitives.ReadUInt32LittleEndian(bytes.Slice(idOffset, 4)) != 0 ||
            contentOffset >= entryEnd)
        {
            return false;
        }

        var reader = new DwarfEncodedReader(
            bytes.Slice(contentOffset, entryEnd - contentOffset),
            ehFrame.VirtualAddress + (uint)contentOffset,
            ehFrame.VirtualAddress);
        if (!reader.TryReadByte(out _))
        {
            return false;
        }

        var augmentation = reader.ReadNullTerminatedString();
        if (augmentation is null ||
            !reader.TryReadUleb128(out _) ||
            !reader.TryReadSleb128(out _) ||
            !reader.TryReadUleb128(out _))
        {
            return false;
        }

        if (!augmentation.StartsWith("z", StringComparison.Ordinal))
        {
            pointerEncoding = 0;
            return true;
        }

        if (!reader.TryReadUleb128(out var augmentationLength) ||
            augmentationLength > int.MaxValue ||
            reader.Remaining < (int)augmentationLength)
        {
            return false;
        }

        var augmentationEnd = reader.Offset + (int)augmentationLength;
        foreach (var item in augmentation.Skip(1))
        {
            switch (item)
            {
                case 'L':
                    if (!reader.TryReadByte(out _))
                    {
                        return false;
                    }

                    break;
                case 'P':
                    if (!reader.TryReadByte(out var personalityEncoding) ||
                        !reader.TryReadEncoded(personalityEncoding, out _))
                    {
                        return false;
                    }

                    break;
                case 'R':
                    if (!reader.TryReadByte(out pointerEncoding))
                    {
                        return false;
                    }

                    return true;
            }

            if (reader.Offset > augmentationEnd)
            {
                return false;
            }
        }

        pointerEncoding = 0;
        return true;
    }

    private static bool TryReadFrameEntryHeader(
        ReadOnlySpan<byte> bytes,
        int entryOffset,
        out int idOffset,
        out int contentOffset,
        out int entryEnd,
        out bool is64BitLength)
    {
        idOffset = 0;
        contentOffset = 0;
        entryEnd = 0;
        is64BitLength = false;
        if (entryOffset < 0 || entryOffset + 4 > bytes.Length)
        {
            return false;
        }

        var length = BinaryPrimitives.ReadUInt32LittleEndian(bytes.Slice(entryOffset, 4));
        if (length == 0)
        {
            return false;
        }

        if (length == 0xFFFFFFFF)
        {
            if (entryOffset + 12 > bytes.Length)
            {
                return false;
            }

            is64BitLength = true;
            var length64 = BinaryPrimitives.ReadUInt64LittleEndian(bytes.Slice(entryOffset + 4, 8));
            if (length64 > int.MaxValue)
            {
                return false;
            }

            idOffset = entryOffset + 12;
            entryEnd = checked(idOffset + (int)length64);
            contentOffset = idOffset + 8;
        }
        else
        {
            idOffset = entryOffset + 4;
            entryEnd = checked(idOffset + (int)length);
            contentOffset = idOffset + 4;
        }

        return entryEnd <= bytes.Length && contentOffset <= entryEnd;
    }

    private static ReadOnlySpan<byte> SliceFile(byte[] fileBytes, ulong offset, ulong size)
    {
        if (offset > (ulong)fileBytes.Length)
        {
            return ReadOnlySpan<byte>.Empty;
        }

        var available = (ulong)fileBytes.Length - offset;
        var length = checked((int)Math.Min(size, available));
        return fileBytes.AsSpan(checked((int)offset), length);
    }

    private static string ReadString(ReadOnlySpan<byte> bytes, uint offset)
    {
        if (offset >= bytes.Length)
        {
            return string.Empty;
        }

        var tail = bytes[(int)offset..];
        var length = tail.IndexOf((byte)0);
        if (length < 0)
        {
            length = tail.Length;
        }

        return Encoding.ASCII.GetString(tail[..length]);
    }

    private sealed record ElfSectionHeaderTable(IReadOnlyList<ElfSectionHeader> Headers, ushort SectionNameIndex);

    private sealed record ElfSectionHeader(
        uint NameOffset,
        uint Type,
        ulong Address,
        ulong Offset,
        ulong Size,
        ulong EntrySize);

    private sealed class DwarfEncodedReader
    {
        private const byte DwEhPeOmit = 0xFF;
        private const byte DwEhPeAbsptr = 0x00;
        private const byte DwEhPeUleb128 = 0x01;
        private const byte DwEhPeUdata2 = 0x02;
        private const byte DwEhPeUdata4 = 0x03;
        private const byte DwEhPeUdata8 = 0x04;
        private const byte DwEhPeSleb128 = 0x09;
        private const byte DwEhPeSdata2 = 0x0A;
        private const byte DwEhPeSdata4 = 0x0B;
        private const byte DwEhPeSdata8 = 0x0C;
        private const byte DwEhPePcrel = 0x10;
        private const byte DwEhPeDatarel = 0x30;
        private readonly ReadOnlyMemory<byte> _bytes;
        private readonly uint _baseAddress;
        private readonly uint _dataRelativeBase;

        public DwarfEncodedReader(ReadOnlySpan<byte> bytes, uint baseAddress, uint dataRelativeBase)
        {
            _bytes = bytes.ToArray();
            _baseAddress = baseAddress;
            _dataRelativeBase = dataRelativeBase;
        }

        public int Offset { get; private set; }

        public int Remaining => _bytes.Length - Offset;

        public bool TryReadByte(out byte value)
        {
            value = 0;
            if (Remaining < 1)
            {
                return false;
            }

            value = _bytes.Span[Offset++];
            return true;
        }

        public string? ReadNullTerminatedString()
        {
            var span = _bytes.Span;
            if (Offset >= span.Length)
            {
                return null;
            }

            var end = Offset;
            while (end < span.Length && span[end] != 0)
            {
                end++;
            }

            if (end >= span.Length)
            {
                return null;
            }

            var value = Encoding.ASCII.GetString(span.Slice(Offset, end - Offset));
            Offset = end + 1;
            return value;
        }

        public bool TryReadUleb128(out ulong value)
        {
            value = 0;
            var shift = 0;
            while (Offset < _bytes.Length && shift < 64)
            {
                var current = _bytes.Span[Offset++];
                value |= ((ulong)(current & 0x7F)) << shift;
                if ((current & 0x80) == 0)
                {
                    return true;
                }

                shift += 7;
            }

            return false;
        }

        public bool TryReadSleb128(out long value)
        {
            value = 0;
            var shift = 0;
            byte current = 0;
            while (Offset < _bytes.Length && shift < 64)
            {
                current = _bytes.Span[Offset++];
                value |= ((long)(current & 0x7F)) << shift;
                shift += 7;
                if ((current & 0x80) == 0)
                {
                    if (shift < 64 && (current & 0x40) != 0)
                    {
                        value |= -1L << shift;
                    }

                    return true;
                }
            }

            return false;
        }

        public bool TryReadEncoded(byte encoding, out long value)
        {
            value = 0;
            if (encoding == DwEhPeOmit)
            {
                return false;
            }

            var fieldAddress = checked((long)_baseAddress + Offset);
            long raw;
            switch (encoding & 0x0F)
            {
                case DwEhPeAbsptr:
                    if (!TryReadInt64(out raw))
                    {
                        return false;
                    }

                    break;
                case DwEhPeUleb128:
                    if (!TryReadUleb128(out var uleb))
                    {
                        return false;
                    }

                    raw = checked((long)uleb);
                    break;
                case DwEhPeUdata2:
                    if (Remaining < 2)
                    {
                        return false;
                    }

                    raw = BinaryPrimitives.ReadUInt16LittleEndian(_bytes.Span.Slice(Offset, 2));
                    Offset += 2;
                    break;
                case DwEhPeUdata4:
                    if (Remaining < 4)
                    {
                        return false;
                    }

                    raw = BinaryPrimitives.ReadUInt32LittleEndian(_bytes.Span.Slice(Offset, 4));
                    Offset += 4;
                    break;
                case DwEhPeUdata8:
                    if (!TryReadInt64(out raw))
                    {
                        return false;
                    }

                    break;
                case DwEhPeSleb128:
                    if (!TryReadSleb128(out raw))
                    {
                        return false;
                    }

                    break;
                case DwEhPeSdata2:
                    if (Remaining < 2)
                    {
                        return false;
                    }

                    raw = BinaryPrimitives.ReadInt16LittleEndian(_bytes.Span.Slice(Offset, 2));
                    Offset += 2;
                    break;
                case DwEhPeSdata4:
                    if (Remaining < 4)
                    {
                        return false;
                    }

                    raw = BinaryPrimitives.ReadInt32LittleEndian(_bytes.Span.Slice(Offset, 4));
                    Offset += 4;
                    break;
                case DwEhPeSdata8:
                    if (!TryReadInt64(out raw))
                    {
                        return false;
                    }

                    break;
                default:
                    return false;
            }

            value = raw;
            switch (encoding & 0x70)
            {
                case 0:
                    break;
                case DwEhPePcrel:
                    value = checked(fieldAddress + raw);
                    break;
                case DwEhPeDatarel:
                    value = checked((long)_dataRelativeBase + raw);
                    break;
                default:
                    return false;
            }

            return (encoding & 0x80) == 0;
        }

        private bool TryReadInt64(out long value)
        {
            value = 0;
            if (Remaining < 8)
            {
                return false;
            }

            value = BinaryPrimitives.ReadInt64LittleEndian(_bytes.Span.Slice(Offset, 8));
            Offset += 8;
            return true;
        }
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
        return Create(
            fileBytes,
            header.Name,
            checked((uint)header.VirtualAddress),
            checked((uint)header.VirtualSize),
            rawPointer,
            rawSize);
    }

    public static PeSection Create(
        byte[] fileBytes,
        string name,
        uint virtualAddress,
        uint virtualSize,
        uint rawPointer,
        uint rawSize)
    {
        var available = rawPointer < fileBytes.Length ? fileBytes.Length - (int)rawPointer : 0;
        var length = Math.Min((int)rawSize, available);
        var memoryOffset = rawPointer < fileBytes.Length ? (int)rawPointer : fileBytes.Length;
        return new PeSection(
            name,
            virtualAddress,
            virtualSize,
            rawPointer,
            rawSize,
            new ReadOnlyMemory<byte>(fileBytes, memoryOffset, length));
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
