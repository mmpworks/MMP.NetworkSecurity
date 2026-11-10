using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Nodes;
using NetSec.Bytes;
using NetSec.Trace;

namespace NetSec.Host;

/// <summary>
/// The Show keys boundary for lines already written, in a session file: the JSON twin of TraceRedaction.Hide (modes-design.md section 6.2).
/// Each secrets[] entry that holds hex holds a fingerprint, its length and "toggle" instead. Every other field stays.
/// </summary>
public static class TraceLines
{
    static readonly JsonSerializerOptions Compact = new() { Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping };

    public static string HideLine(string line)
    {
        JsonNode? node = Parse(line);
        return node is not null && HideIn(node) ? node.ToJsonString(Compact) : line;
    }

    /// <summary>True when a secret in the line is hidden, so a replay can say the bytes are gone from that file.</summary>
    public static bool HoldsHiddenKeys(string line) =>
        Parse(line) is { } node && SecretsIn(node).Any(s => s["hidden"] is not null && s["hex"] is null);

    /// <summary>Writes a hidden copy beside the file and returns its path. The original stays as it was written.</summary>
    public static string WriteHiddenCopy(string file)
    {
        string copy = Path.Combine(Path.GetDirectoryName(file)!, Path.GetFileNameWithoutExtension(file) + ".hidden.ndjson");
        using FileStream source = new(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
        using StreamReader reader = new(source);
        using StreamWriter writer = new(copy, append: false);
        for (string? line = reader.ReadLine(); line is not null; line = reader.ReadLine()) writer.WriteLine(HideLine(line));
        return copy;
    }

    /// <summary>One saved line as JSON, or null when the line is not JSON (a file cut short by a crash, for example).</summary>
    public static JsonNode? Parse(string line)
    {
        try { return JsonNode.Parse(line); }
        catch (JsonException) { return null; }
    }

    static bool HideIn(JsonNode node)
    {
        bool changed = false;
        foreach (JsonObject secret in SecretsIn(node).Where(s => s["hex"] is JsonValue))
        {
            byte[] bytes = Hex.Decode(secret["hex"]!.GetValue<string>());
            secret.Remove("hex");
            secret["fingerprint"] = TraceRedaction.Fingerprint(bytes);
            secret["length"] = bytes.Length;
            secret["hidden"] = TraceRedaction.HiddenByToggle;
            changed = true;
        }
        return changed;
    }

    /// <summary>Every object in a secrets[] array, at any depth: a trace event, or a frame that wraps one.</summary>
    static IEnumerable<JsonObject> SecretsIn(JsonNode node)
    {
        if (node is JsonArray list)
        {
            foreach (JsonNode? item in list.ToArray())
                if (item is not null) foreach (JsonObject s in SecretsIn(item)) yield return s;
            yield break;
        }
        if (node is not JsonObject obj) yield break;
        foreach (KeyValuePair<string, JsonNode?> field in obj.ToArray())
        {
            if (field.Key == "secrets" && field.Value is JsonArray secrets)
                foreach (JsonObject s in secrets.OfType<JsonObject>()) yield return s;
            else if (field.Value is not null)
                foreach (JsonObject s in SecretsIn(field.Value)) yield return s;
        }
    }
}
