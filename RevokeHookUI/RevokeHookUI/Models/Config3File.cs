using System.Text.Json.Serialization;

namespace RevokeHookUI.Models;

public sealed class Config3File
{
    public Dictionary<string, Config3Entry> Versions { get; set; } = new();
}

public sealed class Config3Entry
{
    [JsonPropertyName("sig1")]
    public string? Sig1 { get; set; }

    [JsonPropertyName("sig2")]
    public string? Sig2 { get; set; }

    [JsonPropertyName("sig3")]
    public string? Sig3 { get; set; }
}
