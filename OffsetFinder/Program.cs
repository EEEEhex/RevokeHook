using RevokeHookUI.Services;
using RevokeHookUI.Models;

// Usage: OffsetFinder.exe <Weixin.dll path> [Config3.json path]
string wechatDllPath = args.Length > 0 ? args[0] : @"D:\software\weixin\Weixin.dll";
string config3Path = args.Length > 1 ? args[1] : @"D:\pythonproject\RevokeHook\RevokeHookUI\RevokeHookUI\Config3.json";

Console.WriteLine($"=== RevokeHook Offset Finder ===");
Console.WriteLine($"Target: {wechatDllPath}");
Console.WriteLine($"Config3: {config3Path}");
Console.WriteLine();

if (!File.Exists(wechatDllPath))
{
    Console.WriteLine($"ERROR: Weixin.dll not found at {wechatDllPath}");
    Console.WriteLine("Usage: OffsetFinder.exe <path to Weixin.dll> [path to Config3.json]");
    return 1;
}

if (!File.Exists(config3Path))
{
    Console.WriteLine($"ERROR: Config3.json not found at {config3Path}");
    return 1;
}

try
{
    // Load Config3
    var config3 = Config3Service.Load(config3Path);
    Console.WriteLine($"Config3 versions: {config3.Versions.Count}");

    // Try to match a version
    string? version;
    Config3Entry? entry;
    if (!Config3Service.TryGet(config3, null, out version, out entry) || entry is null)
    {
        Console.WriteLine("ERROR: No valid version found in Config3.json");
        return 1;
    }
    Console.WriteLine($"Using signatures from version: {version}");

    if (string.IsNullOrWhiteSpace(entry.Sig1) || entry.Sig1!.Contains("TODO"))
    {
        Console.WriteLine($"ERROR: Sig1 for version {version} is TODO/empty. Need to reverse-engineer encrypted strings first.");
        Console.WriteLine("See IdaScript/README.md for instructions.");
        return 1;
    }

    Console.WriteLine($"Sig1: {entry.Sig1!.Substring(0, Math.Min(60, entry.Sig1.Length))}...");
    Console.WriteLine($"Sig2: {entry.Sig2!.Substring(0, Math.Min(60, entry.Sig2.Length))}...");
    Console.WriteLine($"Sig3: {entry.Sig3!.Substring(0, Math.Min(60, entry.Sig3.Length))}...");
    Console.WriteLine();

    // Run search
    var request = new CallChainSearchRequest(entry.Sig1, entry.Sig2, entry.Sig3);
    var progress = new Progress<CallChainSearchProgress>(p =>
        Console.WriteLine($"  [{p.Percent}%] {p.Message}"));

    Console.WriteLine("Searching...");
    var result = CallChainSearchService.Search(wechatDllPath, request, progress);
    Console.WriteLine();

    // Print results
    Console.WriteLine($"Native Capstone: {result.UsedNativeCapstone}");
    Console.WriteLine();
    Console.WriteLine($"=== Candidate Counts ===");
    foreach (var kv in result.CandidateCounts)
        Console.WriteLine($"  {kv.Key}: {kv.Value}");

    Console.WriteLine();
    Console.WriteLine($"=== Functions Found ===");
    PrintFunction(result.OriginFunction);
    PrintFunction(result.DeleteMessagesFunction);
    PrintFunction(result.AddMessageToDbFunction);

    Console.WriteLine();
    Console.WriteLine($"=== Call Chains ===");
    if (result.DeleteMessagesChain is not null)
    {
        Console.WriteLine(result.DeleteMessagesChain.Format());
        Console.WriteLine();
        Console.WriteLine($">>> DelMsgOffset = 0x{result.DeleteMessagesChain.RootCallRva:X}");
    }
    else
        Console.WriteLine("DeleteMessages chain: NOT FOUND");

    Console.WriteLine();
    if (result.AddMessageToDbChain is not null)
    {
        Console.WriteLine(result.AddMessageToDbChain.Format());
        Console.WriteLine();
        Console.WriteLine($">>> Add2DBOffset = 0x{result.AddMessageToDbChain.TargetCallRva:X}");
    }
    else
        Console.WriteLine("CoAddMessageToDB chain: NOT FOUND");

    Console.WriteLine();
    Console.WriteLine("=== INI Entry ===");
    Console.WriteLine("Copy this to RevokeHook.ini:");
    Console.WriteLine($"[KeyFunc]");
    Console.WriteLine($"DelMsgOffset=0x{result.DeleteMessagesChain?.RootCallRva ?? 0:X}");
    Console.WriteLine($"Add2DBOffset=0x{result.AddMessageToDbChain?.TargetCallRva ?? 0:X}");

    return 0;
}
catch (Exception ex)
{
    Console.WriteLine($"ERROR: {ex.Message}");
    Console.WriteLine(ex.StackTrace);
    return 1;
}

static void PrintFunction(LocatedFunction f)
{
    Console.WriteLine($"  {f.Name}:");
    Console.WriteLine($"    StringFile=0x{f.StringFileOffset:X}, StringRVA=0x{f.StringRva:X}");
    Console.WriteLine($"    LeaFile=0x{f.LeaFileOffset:X}, LeaRVA=0x{f.LeaRva:X}, FuncRVA=0x{f.FunctionRva:X}");
    Console.WriteLine($"    Insn: {f.LeaInstructionText}");
}