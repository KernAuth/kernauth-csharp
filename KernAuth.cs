using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;

sealed class KernAuth {
  static readonly string[] Fields = ["protocol_version", "entitlement_id", "application_id", "license_id", "status",
    "features", "device_id", "issued_at", "expires_at", "server_time", "nonce", "key_id"];

  public string Api { get; }
  public string AppId { get; }
  public string PublicKey { get; }
  public bool Success { get; private set; }
  public string Message { get; private set; } = "";
  public string Status { get; private set; } = "";
  public string Features { get; private set; } = "";
  public string LicenseId { get; private set; } = "";
  public string ExpiresAt { get; private set; } = "";
  string? installation;

  public KernAuth(string api, string appId, string publicKey) {
    Api = api;
    AppId = appId;
    PublicKey = publicKey;
  }

  public Task<bool> Validate(string license) => Call("validate", license, "License is active");

  public async Task Heartbeat(string license) {
    var bound = Installation();
    var nonce = Convert.ToHexString(RandomNumberGenerator.GetBytes(24)).ToLowerInvariant();
    var fingerprint = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes($"kernauth-device-v1:{bound}"))).ToLowerInvariant();
    var body = new { protocol_version = 1, public_app_id = AppId, client_version = "1.0.0", license_key = license,
      fingerprint_version = 1, device_fingerprint = fingerprint, installation_id = bound, nonce };
    using var client = new HttpClient { Timeout = TimeSpan.FromSeconds(10) };
    using var response = await client.PostAsync($"{Api}/v1/client/heartbeat",
      new StringContent(JsonSerializer.Serialize(body), Encoding.UTF8, "application/json"));
    var text = await response.Content.ReadAsStringAsync();
    if (!response.IsSuccessStatusCode) throw new Exception(ApiMessage(text, $"heartbeat failed ({(int)response.StatusCode})"));
    using var parsed = JsonDocument.Parse(text);
    if (!parsed.RootElement.TryGetProperty("ok", out var ok) || ok.ValueKind != JsonValueKind.True) {
      throw new Exception("heartbeat failed");
    }
  }

  public static void RunVectors() {
    var path = Path.GetFullPath("vectors.json");
    using var fixture = JsonDocument.Parse(File.ReadAllText(path));
    foreach (var vector in fixture.RootElement.GetProperty("vectors").EnumerateArray()) {
      var ent = vector.GetProperty("fields");
      if (Encoding.UTF8.GetString(Canonical(ent)) != vector.GetProperty("canonical").GetString()) throw new Exception("Canonical bytes differ");
      using var grant = JsonDocument.Parse(JsonSerializer.Serialize(new {
        entitlement = ent, signature = vector.GetProperty("signature").GetString()
      }));
      var nonce = ent.GetProperty("nonce").GetString()!;
      var name = ent.GetProperty("application_id").GetString()!;
      var publicKey = vector.GetProperty("public_key").GetString()!;
      var now = DateTimeOffset.Parse("2026-01-01T00:01:00Z");
      if (!Verify(grant.RootElement, nonce, name, publicKey, now) ||
          Verify(grant.RootElement, "wrong", name, publicKey, now) ||
          Verify(grant.RootElement, nonce, "pub_other_app", publicKey, now) ||
          Verify(grant.RootElement, nonce, name, publicKey, now.AddMinutes(20))) throw new Exception("Vector verification failed");
      using var forged = JsonDocument.Parse(JsonSerializer.Serialize(new {
        entitlement = ent, signature = vector.GetProperty("signature").GetString() + "AA"
      }));
      if (Verify(forged.RootElement, nonce, name, publicKey, now)) throw new Exception("Bad signature accepted");
    }
    Console.WriteLine("C# vectors passed");
  }

  string Installation() {
    if (installation != null) return installation;
    var fromEnv = Environment.GetEnvironmentVariable("KERN_INSTALLATION_ID");
    if (!string.IsNullOrWhiteSpace(fromEnv) && Acceptable(fromEnv.Trim())) {
      installation = fromEnv.Trim();
      return installation;
    }
    if (OperatingSystem.IsWindows()) {
      var sid = WindowsIdentity.GetCurrent().User?.Value?.Trim() ?? "";
      if (Acceptable(sid)) {
        installation = sid;
        return installation;
      }
    }
    throw new Exception("Could not read the HWID");
  }

  static bool Acceptable(string value) {
    if (value.Length is < 8 or > 64) return false;
    foreach (var cell in value) {
      if (cell is (>= 'A' and <= 'Z') or (>= 'a' and <= 'z') or (>= '0' and <= '9') or '_' or '-') continue;
      return false;
    }
    return true;
  }

  static string ApiMessage(string raw, string fallback) {
    try {
      using var parsed = JsonDocument.Parse(raw);
      if (parsed.RootElement.TryGetProperty("error", out var error) &&
          error.TryGetProperty("message", out var message) &&
          message.ValueKind == JsonValueKind.String &&
          !string.IsNullOrWhiteSpace(message.GetString())) {
        return message.GetString()!;
      }
    } catch (JsonException) {
    }
    return fallback;
  }

  async Task<bool> Call(string mode, string license, string okMessage) {
    try {
      await Post(mode, license);
      Success = true;
      Message = okMessage;
      return true;
    } catch (Exception error) {
      Success = false;
      Message = error.Message;
      return false;
    }
  }

  async Task Post(string mode, string license) {
    var bound = Installation();
    var nonce = Convert.ToHexString(RandomNumberGenerator.GetBytes(24)).ToLowerInvariant();
    var fingerprint = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes($"kernauth-device-v1:{bound}"))).ToLowerInvariant();
    var body = new { protocol_version = 1, public_app_id = AppId, client_version = "1.0.0", license_key = license,
      save_hwid = true, fingerprint_version = 1, device_fingerprint = fingerprint, installation_id = bound, nonce };
    using var client = new HttpClient { Timeout = TimeSpan.FromSeconds(10) };
    using var response = await client.PostAsync($"{Api}/v1/client/{mode}",
      new StringContent(JsonSerializer.Serialize(body), Encoding.UTF8, "application/json"));
    var text = await response.Content.ReadAsStringAsync();
    if (!response.IsSuccessStatusCode) throw new Exception(ApiMessage(text, $"{mode} failed ({(int)response.StatusCode})"));
    using var parsed = JsonDocument.Parse(text);
    if (!Verify(parsed.RootElement, nonce, AppId, PublicKey, DateTimeOffset.UtcNow)) {
      throw new Exception("Invalid or expired signed entitlement");
    }
    var ent = parsed.RootElement.GetProperty("entitlement");
    Status = ent.GetProperty("status").GetString() ?? "";
    var feature = ent.GetProperty("features");
    Features = CanonicalFeatures(feature.ValueKind == JsonValueKind.String
      ? JsonDocument.Parse(feature.GetString()!).RootElement : feature);
    LicenseId = ent.GetProperty("license_id").GetString() ?? "";
    ExpiresAt = ent.GetProperty("expires_at").GetString() ?? "";
  }

  public static byte[] Canonical(JsonElement entitlement) {
    var lines = new StringBuilder();
    foreach (var name in Fields) {
      var element = entitlement.GetProperty(name);
      var value = name == "features"
        ? CanonicalFeatures(element.ValueKind == JsonValueKind.String
          ? JsonDocument.Parse(element.GetString()!).RootElement : element)
        : element.ValueKind == JsonValueKind.String ? element.GetString()! : element.GetRawText();
      if (value.Contains('\n') || value.Contains('\r')) throw new InvalidDataException("Invalid entitlement field");
      lines.Append(name).Append('=').Append(value).Append('\n');
    }
    return Encoding.UTF8.GetBytes(lines.ToString());
  }

  static string CanonicalFeatures(JsonElement input) {
    using var stream = new MemoryStream();
    using (var writer = new Utf8JsonWriter(stream)) WriteSorted(writer, input);
    return Encoding.UTF8.GetString(stream.ToArray());
  }

  static void WriteSorted(Utf8JsonWriter writer, JsonElement element) {
    if (element.ValueKind == JsonValueKind.Object) {
      writer.WriteStartObject();
      foreach (var property in element.EnumerateObject().OrderBy(p => p.Name, StringComparer.Ordinal)) {
        writer.WritePropertyName(property.Name);
        WriteSorted(writer, property.Value);
      }
      writer.WriteEndObject();
    } else if (element.ValueKind == JsonValueKind.Array) {
      writer.WriteStartArray();
      foreach (var item in element.EnumerateArray()) WriteSorted(writer, item);
      writer.WriteEndArray();
    } else element.WriteTo(writer);
  }

  public static bool Verify(JsonElement grant, string nonce, string expectedApp, string pinnedKey, DateTimeOffset now) {
    try {
      var ent = grant.GetProperty("entitlement");
      if (ent.GetProperty("protocol_version").GetInt32() != 1 ||
          ent.GetProperty("nonce").GetString() != nonce ||
          ent.GetProperty("application_id").GetString() != expectedApp ||
          ent.GetProperty("status").GetString() != "active" ||
          DateTimeOffset.Parse(ent.GetProperty("expires_at").GetString()!) <= now) return false;
      var key = new Ed25519PublicKeyParameters(Convert.FromBase64String(pinnedKey), 0);
      var signature = Convert.FromBase64String(grant.GetProperty("signature").GetString()!);
      var message = Canonical(ent);
      var verifier = new Ed25519Signer(); verifier.Init(false, key);
      verifier.BlockUpdate(message, 0, message.Length);
      return verifier.VerifySignature(signature);
    } catch { return false; }
  }
}
