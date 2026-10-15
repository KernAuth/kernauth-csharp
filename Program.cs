using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;

const string Api = "https://api.kernauth.com";
const string AppId = "__PUBLIC_APP_ID__";
const string PublicKey = "__PUBLIC_KEY__";

if (args.Contains("--test-vectors")) {
  Vectors();
  return;
}

var app = new KernAuth(Api, AppId, PublicKey);
if (!await app.Validate(LicenseKey(), InstallationId())) {
  throw new Exception(app.Message);
}
Console.WriteLine($"Status: {app.Status}");
Console.WriteLine($"Features: {app.Features}");
Console.WriteLine($"License: {app.LicenseId}");
Console.WriteLine($"Check expires: {app.ExpiresAt}");

static string LicenseKey() {
  var fromEnv = Environment.GetEnvironmentVariable("KERN_LICENSE_KEY");
  if (!string.IsNullOrWhiteSpace(fromEnv)) return fromEnv.Trim();
  if (!Console.IsInputRedirected) Console.Write("Enter license: ");
  return (Console.ReadLine() ?? "").Trim();
}

static string InstallationId() {
  var fromEnv = Environment.GetEnvironmentVariable("KERN_INSTALLATION_ID");
  if (!string.IsNullOrWhiteSpace(fromEnv)) return fromEnv.Trim();
  var hwid = MachineHwid().Trim();
  if (AcceptableHwid(hwid)) return hwid;
  throw new Exception("Could not read the HWID");
}

static bool AcceptableHwid(string value) {
  if (value.Length is < 8 or > 64) return false;
  foreach (var cell in value) {
    if (cell is (>= 'A' and <= 'Z') or (>= 'a' and <= 'z') or (>= '0' and <= '9') or '_' or '-') continue;
    return false;
  }
  return true;
}

static string MachineHwid() {
  if (OperatingSystem.IsWindows()) return System.Security.Principal.WindowsIdentity.GetCurrent().User?.Value ?? "";
  if (OperatingSystem.IsLinux()) return File.ReadAllText("/etc/machine-id");
  if (!OperatingSystem.IsMacOS()) return "";
  var output = System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo {
    FileName = "ioreg", Arguments = "-rd1 -c IOPlatformExpertDevice", RedirectStandardOutput = true, UseShellExecute = false
  })?.StandardOutput.ReadToEnd() ?? "";
  var marker = "\"IOPlatformUUID\" = \"";
  var start = output.IndexOf(marker, StringComparison.Ordinal);
  if (start < 0) return "";
  start += marker.Length;
  var end = output.IndexOf('"', start);
  return end < 0 ? "" : output[start..end];
}

void Vectors() {
  var path = Path.GetFullPath("vectors.json");
  using var fixture = JsonDocument.Parse(File.ReadAllText(path));
  foreach (var vector in fixture.RootElement.GetProperty("vectors").EnumerateArray()) {
    var ent = vector.GetProperty("fields");
    if (Encoding.UTF8.GetString(KernAuth.Canonical(ent)) != vector.GetProperty("canonical").GetString()) throw new Exception("Canonical bytes differ");
    using var grant = JsonDocument.Parse(JsonSerializer.Serialize(new {
      entitlement = ent, signature = vector.GetProperty("signature").GetString()
    }));
    var nonce = ent.GetProperty("nonce").GetString()!;
    var name = ent.GetProperty("application_id").GetString()!;
    var publicKey = vector.GetProperty("public_key").GetString()!;
    var now = DateTimeOffset.Parse("2026-01-01T00:01:00Z");
    if (!KernAuth.Verify(grant.RootElement, nonce, name, publicKey, now) ||
        KernAuth.Verify(grant.RootElement, "wrong", name, publicKey, now) ||
        KernAuth.Verify(grant.RootElement, nonce, "pub_other_app", publicKey, now) ||
        KernAuth.Verify(grant.RootElement, nonce, name, publicKey, now.AddMinutes(20))) throw new Exception("Vector verification failed");
    using var forged = JsonDocument.Parse(JsonSerializer.Serialize(new {
      entitlement = ent, signature = vector.GetProperty("signature").GetString() + "AA"
    }));
    if (KernAuth.Verify(forged.RootElement, nonce, name, publicKey, now)) throw new Exception("Bad signature accepted");
  }
  Console.WriteLine("C# vectors passed");
}

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

  public KernAuth(string api, string appId, string publicKey) {
    Api = api;
    AppId = appId;
    PublicKey = publicKey;
  }

  public Task<bool> Validate(string license, string installation) => Call("validate", license, installation, "License is active");

  async Task<bool> Call(string mode, string license, string installation, string okMessage) {
    try {
      await Post(mode, license, installation);
      Success = true;
      Message = okMessage;
      return true;
    } catch (Exception error) {
      Success = false;
      Message = error.Message;
      return false;
    }
  }

  async Task Post(string mode, string license, string installation) {
    var nonce = Convert.ToHexString(RandomNumberGenerator.GetBytes(24)).ToLowerInvariant();
    var fingerprint = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes($"kernauth-device-v1:{installation}"))).ToLowerInvariant();
    var body = new { protocol_version = 1, public_app_id = AppId, client_version = "1.0.0", license_key = license,
      fingerprint_version = 1, device_fingerprint = fingerprint, installation_id = installation, nonce };
    using var client = new HttpClient { Timeout = TimeSpan.FromSeconds(10) };
    using var response = await client.PostAsync($"{Api}/v1/client/{mode}",
      new StringContent(JsonSerializer.Serialize(body), Encoding.UTF8, "application/json"));
    response.EnsureSuccessStatusCode();
    using var parsed = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
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
