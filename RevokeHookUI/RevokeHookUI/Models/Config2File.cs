using System.Text.Json.Serialization;

namespace RevokeHookUI.Models;

public sealed class Config2File
{
    [JsonPropertyName("general")]
    public Dictionary<string, Config2GeneralEntry> General { get; set; } = new();

    [JsonPropertyName("specific")]
    public Dictionary<string, Config2SpecificEntry> Specific { get; set; } = new();
}

public sealed class Config2GeneralEntry
{
    [JsonPropertyName("sig1")]
    public string? Sig1 { get; set; }

    [JsonPropertyName("sig2")]
    public string? Sig2 { get; set; }

    [JsonPropertyName("sig1_delta")]
    public string? Sig1Delta { get; set; }

    [JsonPropertyName("sig2_delta")]
    public string? Sig2Delta { get; set; }

    [JsonPropertyName("sig1_arg_msg_index")]
    public string? Sig1ArgMsgIndex { get; set; }

    [JsonPropertyName("sig1_offset_revoke_xml")]
    public string? Sig1OffsetRevokeXml { get; set; }

    [JsonPropertyName("sig2_arg_msg_index")]
    public string? Sig2ArgMsgIndex { get; set; }

    [JsonPropertyName("sig2_arg_bool_index")]
    public string? Sig2ArgBoolIndex { get; set; }

    [JsonPropertyName("sig2_offset_revoke_xml")]
    public string? Sig2OffsetRevokeXml { get; set; }

    [JsonPropertyName("sig2_offset_srvid")]
    public string? Sig2OffsetSrvId { get; set; }

    [JsonPropertyName("tips")]
    public string? Tips { get; set; }
}

public sealed class Config2SpecificEntry
{
    [JsonPropertyName("KeyFunc")]
    public Config2KeyFuncEntry? KeyFunc { get; set; }

    [JsonPropertyName("DelMsg")]
    public Config2DelMsgEntry? DelMsg { get; set; }

    [JsonPropertyName("Add2DB")]
    public Config2Add2DbEntry? Add2DB { get; set; }
}

public sealed class Config2KeyFuncEntry
{
    [JsonPropertyName("DelMsgOffset")]
    public string? DelMsgOffset { get; set; }

    [JsonPropertyName("Add2DBOffset")]
    public string? Add2DBOffset { get; set; }
}

public sealed class Config2DelMsgEntry
{
    [JsonPropertyName("ArgMsgIndex")]
    public string? ArgMsgIndex { get; set; }

    [JsonPropertyName("OffsetRevokeXML")]
    public string? OffsetRevokeXml { get; set; }
}

public sealed class Config2Add2DbEntry
{
    [JsonPropertyName("ArgMsgIndex")]
    public string? ArgMsgIndex { get; set; }

    [JsonPropertyName("ArgBoolIndex")]
    public string? ArgBoolIndex { get; set; }

    [JsonPropertyName("OffsetRevokeXML")]
    public string? OffsetRevokeXml { get; set; }

    [JsonPropertyName("OffsetSrvID")]
    public string? OffsetSrvId { get; set; }
}
