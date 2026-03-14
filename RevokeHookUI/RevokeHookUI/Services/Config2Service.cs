using System.IO;
using System.Text.Json;
using RevokeHookUI.Models;

namespace RevokeHookUI.Services;

public static class Config2Service
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true,
        ReadCommentHandling = JsonCommentHandling.Skip,
        AllowTrailingCommas = true
    };

    public static Config2File Load(string path)
    {
        var json = File.ReadAllText(path);
        return Parse(json);
    }

    public static Config2File Parse(string json)
    {
        var config = JsonSerializer.Deserialize<Config2File>(json, JsonOptions);
        return config ?? new Config2File();
    }

    public static bool TryGetGeneral(
        Config2File config,
        string? preferredVersion,
        out string version,
        out Config2GeneralEntry entry)
    {
        return TrySelect(config.General, preferredVersion, out version, out entry);
    }

    public static bool TryGetSpecific(
        Config2File config,
        string? preferredVersion,
        out string version,
        out Config2SpecificEntry entry)
    {
        return TrySelect(config.Specific, preferredVersion, out version, out entry);
    }

    private static bool TrySelect<T>(
        IReadOnlyDictionary<string, T> values,
        string? preferredVersion,
        out string version,
        out T entry)
    {
        if (values.Count == 0)
        {
            version = string.Empty;
            entry = default!;
            return false;
        }

        if (!string.IsNullOrWhiteSpace(preferredVersion))
        {
            var preferredKey = values.Keys.FirstOrDefault(key =>
                string.Equals(NormalizeVersion(key), NormalizeVersion(preferredVersion), StringComparison.Ordinal));

            if (preferredKey is not null)
            {
                version = preferredKey;
                entry = values[preferredKey];
                return true;
            }

            if (TryParseVersion(preferredVersion, out var preferredParts))
            {
                var parsedCandidates = values.Keys
                    .Select(key => new
                    {
                        Key = key,
                        Parsed = TryParseVersion(key, out var keyParts),
                        Parts = keyParts
                    })
                    .Where(candidate => candidate.Parsed)
                    .ToList();

                var lowerOrEqual = parsedCandidates
                    .Where(candidate => CompareVersions(candidate.Parts, preferredParts) <= 0)
                    .OrderByDescending(candidate => candidate.Parts, VersionPartsComparer.Instance)
                    .FirstOrDefault();

                if (lowerOrEqual is not null)
                {
                    version = lowerOrEqual.Key;
                    entry = values[version];
                    return true;
                }

                var greater = parsedCandidates
                    .Where(candidate => CompareVersions(candidate.Parts, preferredParts) > 0)
                    .OrderBy(candidate => candidate.Parts, VersionPartsComparer.Instance)
                    .FirstOrDefault();

                if (greater is not null)
                {
                    version = greater.Key;
                    entry = values[version];
                    return true;
                }
            }
        }

        version = values.Keys
            .OrderByDescending(VersionSortKey)
            .First();
        entry = values[version];
        return true;
    }

    private static string NormalizeVersion(string version)
    {
        var parts = version.Split('.', StringSplitOptions.RemoveEmptyEntries);
        return string.Join('.', parts.Select(part => int.TryParse(part, out var value) ? value.ToString() : part));
    }

    private static string VersionSortKey(string version)
    {
        var parts = version.Split('.', StringSplitOptions.RemoveEmptyEntries)
            .Select(part => int.TryParse(part, out var value) ? value.ToString("D5") : part)
            .ToArray();
        return string.Join('.', parts);
    }

    private static bool TryParseVersion(string version, out int[] parts)
    {
        var tokens = version.Split('.', StringSplitOptions.RemoveEmptyEntries);
        var values = new int[tokens.Length];

        for (var index = 0; index < tokens.Length; index++)
        {
            if (!int.TryParse(tokens[index], out values[index]))
            {
                parts = Array.Empty<int>();
                return false;
            }
        }

        parts = values;
        return values.Length > 0;
    }

    private static int CompareVersions(IReadOnlyList<int> left, IReadOnlyList<int> right)
    {
        var maxLength = Math.Max(left.Count, right.Count);
        for (var index = 0; index < maxLength; index++)
        {
            var leftValue = index < left.Count ? left[index] : 0;
            var rightValue = index < right.Count ? right[index] : 0;

            if (leftValue != rightValue)
            {
                return leftValue.CompareTo(rightValue);
            }
        }

        return 0;
    }

    private sealed class VersionPartsComparer : IComparer<IReadOnlyList<int>>
    {
        public static VersionPartsComparer Instance { get; } = new();

        public int Compare(IReadOnlyList<int>? x, IReadOnlyList<int>? y)
        {
            if (ReferenceEquals(x, y))
            {
                return 0;
            }

            if (x is null)
            {
                return -1;
            }

            if (y is null)
            {
                return 1;
            }

            return CompareVersions(x, y);
        }
    }
}
