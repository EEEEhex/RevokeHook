using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;

namespace RevokeHookUI.Services;

public sealed record UpdateCheckResult(
    string CurrentVersion,
    string LatestVersion,
    bool HasUpdate,
    string ReleaseUrl);

public static class UpdateCheckService
{
    public const string CurrentVersion = "v4.1.0";

    private const string DefaultLatestReleaseApiUrl = "https://api.github.com/repos/EEEEhex/RevokeHook/releases/latest";

    public static async Task<UpdateCheckResult> CheckForUpdatesAsync(CancellationToken cancellationToken = default)
    {
        using var client = CreateHttpClient();
        var apiUrl = Environment.GetEnvironmentVariable("REVOKEHOOK_RELEASES_API_URL");
        if (string.IsNullOrWhiteSpace(apiUrl))
        {
            apiUrl = DefaultLatestReleaseApiUrl;
        }

        using var response = await client.GetAsync(apiUrl, cancellationToken);
        response.EnsureSuccessStatusCode();

        var content = await response.Content.ReadAsStringAsync(cancellationToken);
        var payload = JsonSerializer.Deserialize<GithubReleasePayload>(content)
            ?? throw new InvalidDataException("GitHub releases 返回为空。");

        if (string.IsNullOrWhiteSpace(payload.TagName))
        {
            throw new InvalidDataException("GitHub releases 缺少 tag_name。");
        }

        var latestVersion = payload.TagName.Trim();
        var hasUpdate = CompareVersionTags(latestVersion, CurrentVersion) > 0;

        return new UpdateCheckResult(
            CurrentVersion,
            latestVersion,
            hasUpdate,
            payload.HtmlUrl ?? string.Empty);
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
            Timeout = TimeSpan.FromSeconds(20)
        };

        client.DefaultRequestHeaders.UserAgent.Add(new ProductInfoHeaderValue("RevokeHookUI", "4.1.0"));
        client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/vnd.github+json"));
        return client;
    }

    private static int CompareVersionTags(string left, string right)
    {
        var leftParts = ExtractVersionNumbers(left);
        var rightParts = ExtractVersionNumbers(right);
        var maxLength = Math.Max(leftParts.Count, rightParts.Count);

        for (var index = 0; index < maxLength; index++)
        {
            var leftValue = index < leftParts.Count ? leftParts[index] : 0;
            var rightValue = index < rightParts.Count ? rightParts[index] : 0;

            if (leftValue != rightValue)
            {
                return leftValue.CompareTo(rightValue);
            }
        }

        return 0;
    }

    private static List<int> ExtractVersionNumbers(string version)
    {
        return Regex.Matches(version, @"\d+")
            .Select(match => int.Parse(match.Value))
            .ToList();
    }

    private sealed class GithubReleasePayload
    {
        [JsonPropertyName("tag_name")]
        public string? TagName { get; set; }

        [JsonPropertyName("html_url")]
        public string? HtmlUrl { get; set; }
    }
}
