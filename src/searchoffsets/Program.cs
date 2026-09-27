using RevokeHookTUI.Models;
using RevokeHookTUI.Services;

namespace SearchOffsets;

internal static class Program
{
    private static int Main(string[] args)
    {
        // 用法: searchoffsets <微信二进制路径> [版本号] [config3.json路径]
        if (args.Length < 1)
        {
            Console.Error.WriteLine("用法: searchoffsets <微信二进制路径> [版本号] [Config3.json路径]");
            return 1;
        }

        var binaryPath = args[0];
        var version = args.Length > 1 ? args[1] : "4.1.13.23";
        var configPath = args.Length > 2 ? args[2]
            : Path.Combine(AppContext.BaseDirectory, "Config3.json");

        if (!File.Exists(binaryPath))
        {
            Console.Error.WriteLine($"二进制不存在: {binaryPath}");
            return 1;
        }
        if (!File.Exists(configPath))
        {
            Console.Error.WriteLine($"Config3.json 不存在: {configPath}");
            return 1;
        }

        Config3File config3;
        try
        {
            config3 = Config3Service.Load(configPath);
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"解析 Config3.json 失败: {ex.Message}");
            return 1;
        }

        if (!config3.Versions.TryGetValue(version, out var entry))
        {
            Console.Error.WriteLine($"Config3.json 中未找到版本: {version}. 可用: {string.Join(", ", config3.Versions.Keys)}");
            return 1;
        }

        var sig1 = entry.Sig1 ?? "";
        var sig2 = entry.Sig2 ?? "";
        var sig3 = entry.Sig3 ?? "";
        Console.WriteLine($"版本: {version}");
        Console.WriteLine($"二进制: {binaryPath}");
        Console.WriteLine("开始搜索偏移...");

        var request = new CallChainSearchRequest(sig1, sig2, sig3);
        var progress = new Progress<CallChainSearchProgress>(p =>
        {
            Console.WriteLine($"[{p.Percent,3}%] {p.Message}");
        });

        CallChainSearchResult result;
        try
        {
            result = CallChainSearchService.Search(binaryPath, request, progress);
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"搜索失败: {ex.Message}");
            Console.Error.WriteLine(ex.StackTrace);
            return 1;
        }

        Console.WriteLine();
        Console.WriteLine("========== 搜索结果 ==========");
        Console.WriteLine($"UseNativeCapstone: {result.UsedNativeCapstone}");
        foreach (var kv in result.CandidateCounts)
        {
            Console.WriteLine($"  {kv.Key} 候选函数: {kv.Value}");
        }

        Console.WriteLine();
        Console.WriteLine($"OriginFunction          : RVA=0x{result.OriginFunction.FunctionRva:X}");
        Console.WriteLine($"DeleteMessages 函数      : RVA=0x{result.DeleteMessagesFunction.FunctionRva:X}");
        Console.WriteLine($"AddMessageToDb 函数      : RVA=0x{result.AddMessageToDbFunction.FunctionRva:X}");

        uint? delMsg = result.DeleteMessagesChain?.RootCallRva;
        uint? add2db = result.AddMessageToDbChain?.TargetCallRva;

        Console.WriteLine();
        if (delMsg.HasValue)
        {
            Console.WriteLine($"DelMsgOffset (DeleteMessagesChain.RootCallRva) = 0x{delMsg.Value:X}  ({delMsg.Value})");
            Console.WriteLine("调用链:");
            Console.WriteLine(result.DeleteMessagesChain!.Format());
        }
        else
        {
            Console.WriteLine("DelMsgOffset: 未在三层调用深度内找到 DeleteMessages 调用链!");
        }

        Console.WriteLine();
        if (add2db.HasValue)
        {
            Console.WriteLine($"Add2DBOffset (AddMessageToDbChain.TargetCallRva) = 0x{add2db.Value:X}  ({add2db.Value})");
            Console.WriteLine("调用链:");
            Console.WriteLine(result.AddMessageToDbChain!.Format());
        }
        else
        {
            Console.WriteLine("Add2DBOffset: 未在三层调用深度内找到 AddMessageToDb 调用链!");
        }

        // 输出可直接用于 RevokeHook.ini 的值
        if (delMsg.HasValue && add2db.HasValue)
        {
            Console.WriteLine();
            Console.WriteLine("== 写入 RevokeHook.ini ==");
            Console.WriteLine("[KeyFunc]");
            Console.WriteLine($"DelMsgOffset={delMsg.Value}");
            Console.WriteLine($"Add2DBOffset={add2db.Value}");
        }

        return (delMsg.HasValue && add2db.HasValue) ? 0 : 2;
    }
}