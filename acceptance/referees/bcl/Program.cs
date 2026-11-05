// The BCL line oracle. It reads one JSON request per line on stdin and writes one
// JSON response per line on stdout. All byte values are lowercase hex. The process
// ends at end of input with exit code 0.
//
// This is an outside referee for the product's hand-written primitives (PRD D10).
// It calls only System.Security.Cryptography and shares no code with the product.
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using NetSec.Referees.Bcl;

using var input = new StreamReader(Console.OpenStandardInput(), new UTF8Encoding(false));
using var output = new StreamWriter(Console.OpenStandardOutput(), new UTF8Encoding(false)) { AutoFlush = true };

while (await input.ReadLineAsync() is { } line)
{
    if (!string.IsNullOrWhiteSpace(line))
    {
        await output.WriteLineAsync(Oracle.Answer(line).ToJsonString());
    }
}

namespace NetSec.Referees.Bcl
{
    /// <summary>Turns one request line into one response object. Every failure has a stable code.</summary>
    internal static class Oracle
    {
        public static JsonObject Answer(string line)
        {
            JsonNode? id = null;
            try
            {
                using JsonDocument document = JsonDocument.Parse(line);
                var request = new Request(document.RootElement);
                id = request.Id;
                return Respond(id, Operations.Run(request));
            }
            catch (OracleException failure)
            {
                return Fail(id, failure.Code, failure.Message);
            }
            catch (JsonException failure)
            {
                return Fail(id, "BAD_REQUEST", failure.Message);
            }
            catch (FormatException failure)
            {
                return Fail(id, "BAD_REQUEST", failure.Message);
            }
            catch (ArgumentException failure)
            {
                return Fail(id, "BAD_REQUEST", failure.Message);
            }
            catch (System.Security.Cryptography.CryptographicException failure)
            {
                return Fail(id, "CRYPTO_ERROR", failure.Message);
            }
        }

        private static JsonObject Respond(JsonNode? id, JsonObject fields)
        {
            var response = new JsonObject { ["id"] = id, ["ok"] = true };
            foreach ((string name, JsonNode? value) in fields.ToArray())
            {
                fields.Remove(name);
                response[name] = value;
            }
            return response;
        }

        private static JsonObject Fail(JsonNode? id, string code, string detail) =>
            new() { ["id"] = id, ["ok"] = false, ["error"] = code, ["detail"] = detail };
    }

    /// <summary>A failure the caller branches on by <see cref="Code"/>.</summary>
    internal sealed class OracleException(string code, string message) : Exception(message)
    {
        public string Code { get; } = code;
    }

    /// <summary>Typed reads over one request object.</summary>
    internal readonly struct Request(JsonElement root)
    {
        public JsonNode? Id => root.TryGetProperty("id", out JsonElement id) ? JsonNode.Parse(id.GetRawText()) : null;

        public string Op => Text("op");

        public string Text(string name) =>
            root.TryGetProperty(name, out JsonElement value) && value.ValueKind == JsonValueKind.String
                ? value.GetString()!
                : throw new OracleException("BAD_REQUEST", $"missing text field '{name}'");

        public string TextOr(string name, string fallback) =>
            root.TryGetProperty(name, out _) ? Text(name) : fallback;

        public int Number(string name) =>
            root.TryGetProperty(name, out JsonElement value) && value.TryGetInt32(out int number)
                ? number
                : throw new OracleException("BAD_REQUEST", $"missing number field '{name}'");

        public int NumberOr(string name, int fallback) =>
            root.TryGetProperty(name, out _) ? Number(name) : fallback;

        public byte[] Hex(string name) => Convert.FromHexString(Text(name));

        public byte[] HexOr(string name, byte[] fallback) =>
            root.TryGetProperty(name, out _) ? Hex(name) : fallback;

        public bool Has(string name) => root.TryGetProperty(name, out _);
    }
}
