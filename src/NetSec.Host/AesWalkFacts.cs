using System.Text.Json;
using NetSec.Bytes;

namespace NetSec.Host;

/// <summary>
/// What a lesson 1 run shows about its key and text, read from the stored trace at each query (docs/walkthrough-design.md section 3.4).
/// It reads the shown line, because the caller has already checked the toggle. A null field means the run has not reached that event.
/// </summary>
public sealed record AesWalkFacts(byte[]? Key, byte[]? Text, byte[]? EcbTextFrame)
{
    const string KeyName = "aes.key", EcbText = "TextEcb";

    public static AesWalkFacts Read(IEnumerable<StoredEvent> events)
    {
        byte[]? key = null, text = null, frame = null;
        foreach (StoredEvent e in events)
        {
            if (key is null && e.Type == "secret.derived") key = SecretIn(e.Line);
            else if (text is null && e.Type == "aes.message.sent") text = BytesIn(e.Line, "plain");
            else if (frame is null && e.Type == "wire.sent" && e.Message == EcbText) frame = BytesIn(e.Line, "wire");
        }
        return new AesWalkFacts(key, text, frame);
    }

    static byte[]? SecretIn(string line)
    {
        using JsonDocument d = JsonDocument.Parse(line);
        if (!d.RootElement.TryGetProperty("secrets", out JsonElement secrets)) return null;
        foreach (JsonElement s in secrets.EnumerateArray())
            if (s.GetProperty("name").GetString() == KeyName && s.TryGetProperty("hex", out JsonElement hex)) return Hex.Decode(hex.GetString()!);
        return null;
    }

    static byte[]? BytesIn(string line, string field)
    {
        using JsonDocument d = JsonDocument.Parse(line);
        return d.RootElement.TryGetProperty(field, out JsonElement value) && value.GetString() is { Length: > 0 } hex ? Hex.Decode(hex) : null;
    }
}
