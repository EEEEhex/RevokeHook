using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.IO;

namespace RevokeHookUI.Services;

public readonly record struct CloudDownloadProgress(string Message, double? Percentage, bool IsIndeterminate);

public static class CloudConfigService
{
    private static readonly string[] CandidateUrls =
    {
        "https://raw.githubusercontent.com/EEEEhex/RevokeHook/main/Config2.json",
        "http://47.109.182.110:8123/api/get_config2"
    };

    public static async Task DownloadLatestConfigAsync(
        string destinationPath,
        IProgress<CloudDownloadProgress>? progress = null,
        CancellationToken cancellationToken = default)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(destinationPath) ?? AppContext.BaseDirectory);

        using var client = CreateHttpClient();
        Exception? lastException = null;

        foreach (var candidateUrl in EnumerateCandidateUrls())
        {
            try
            {
                progress?.Report(new CloudDownloadProgress("正在连接 Url: " + candidateUrl, null, true));
                await DownloadAndValidateAsync(client, candidateUrl, destinationPath, progress, cancellationToken);
                return;
            }
            catch (HttpRequestException ex)
            {
                lastException = ex;
            }
            catch (TaskCanceledException ex)
            {
                lastException = ex;
            }
        }

        throw new InvalidOperationException("无法从云端下载 Config2.json。", lastException);
    }

    private static IEnumerable<string> EnumerateCandidateUrls()
    {
        var overrideUrl = Environment.GetEnvironmentVariable("REVOKEHOOK_CONFIG2_URL");
        if (!string.IsNullOrWhiteSpace(overrideUrl))
        {
            yield return overrideUrl;
        }

        foreach (var candidateUrl in CandidateUrls)
        {
            yield return candidateUrl;
        }
    }

    private static async Task DownloadAndValidateAsync(
        HttpClient client,
        string url,
        string destinationPath,
        IProgress<CloudDownloadProgress>? progress,
        CancellationToken cancellationToken)
    {
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        cts.CancelAfter(TimeSpan.FromSeconds(3));
        using var response = await client.GetAsync(url, HttpCompletionOption.ResponseHeadersRead, cts.Token);
        response.EnsureSuccessStatusCode();

        var totalBytes = response.Content.Headers.ContentLength;
        var tempPath = destinationPath + ".download";

        await using (var source = await response.Content.ReadAsStreamAsync(cancellationToken))
        await using (var target = new FileStream(tempPath, FileMode.Create, FileAccess.Write, FileShare.None))
        {
            var buffer = new byte[81920];
            long totalRead = 0;

            while (true)
            {
                var read = await source.ReadAsync(buffer.AsMemory(0, buffer.Length), cancellationToken);
                if (read == 0)
                {
                    break;
                }

                await target.WriteAsync(buffer.AsMemory(0, read), cancellationToken);
                totalRead += read;

                double? percentage = null;
                var isIndeterminate = true;
                if (totalBytes is > 0)
                {
                    percentage = totalRead * 100d / totalBytes.Value;
                    isIndeterminate = false;
                }

                progress?.Report(new CloudDownloadProgress(
                    $"正在下载 Config2.json ({totalRead / 1024d:F1} KB)",
                    percentage,
                    isIndeterminate));
            }
        }

        var content = await File.ReadAllTextAsync(tempPath, cancellationToken);
        var parsed = Config2Service.Parse(content);
        if (parsed.General.Count == 0)
        {
            File.Delete(tempPath);
            throw new InvalidDataException("下载内容不是有效的 Config2.json。");
        }

        File.Copy(tempPath, destinationPath, true);
        File.Delete(tempPath);
    }

    private static HttpClient CreateHttpClient()
    {
        var proxy = WebRequest.GetSystemWebProxy();
        proxy.Credentials = CredentialCache.DefaultCredentials;

        var handler = new HttpClientHandler
        {
            Proxy = proxy,
            UseProxy = true,
            DefaultProxyCredentials = CredentialCache.DefaultCredentials
        };

        var client = new HttpClient(handler)
        {
            Timeout = TimeSpan.FromSeconds(45)
        };

        client.DefaultRequestHeaders.UserAgent.Add(new ProductInfoHeaderValue("RevokeHookUI", "1.0"));
        client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        return client;
    }
}
