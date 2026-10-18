using System.Security.Cryptography;
using System.Text.Json;

if (args.Contains("--test-vectors")) {
  KernAuth.RunVectors();
  return;
}

var app = new KernAuth("https://api.kernauth.com", "__PUBLIC_APP_ID__", "__PUBLIC_KEY__");
var key = LicenseKey();
if (!await app.Validate(key)) {
  Console.WriteLine(app.Message);
  Environment.Exit(1);
}
using var features = JsonDocument.Parse(app.Features);
if (!TryUnwrap(features.RootElement, out var payloadKey)) {
  Console.WriteLine("The payload key could not open this build.");
  Environment.Exit(1);
}
CryptographicOperations.ZeroMemory(payloadKey);
// Decrypt the program with the opened key. Drop it when the heartbeat fails.
Console.WriteLine("Payload opened");
Console.WriteLine($"Status: {app.Status}");
Console.WriteLine($"License: {app.LicenseId}");
Console.WriteLine($"Check expires: {app.ExpiresAt}");
while (true) {
  await Task.Delay(TimeSpan.FromSeconds(60));
  try {
    await app.Heartbeat(key);
  } catch (Exception error) {
    Console.WriteLine(error.Message);
    Environment.Exit(1);
  }
}

static bool TryUnwrap(JsonElement features, out byte[] payloadKey) {
  payloadKey = Array.Empty<byte>();
  if (!features.TryGetProperty("wrap_key", out var wrapKeyElement)
      || !features.TryGetProperty("payload_box", out var boxElement)
      || wrapKeyElement.ValueKind != JsonValueKind.String
      || boxElement.ValueKind != JsonValueKind.String) {
    return false;
  }
  try {
    var wrapKey = Convert.FromBase64String(wrapKeyElement.GetString() ?? "");
    var box = Convert.FromBase64String(boxElement.GetString() ?? "");
    if (wrapKey.Length != 32 || box.Length <= 28) return false;
    var nonce = box.AsSpan(0, 12);
    var cipher = box.AsSpan(12, box.Length - 28);
    var tag = box.AsSpan(box.Length - 16);
    payloadKey = new byte[cipher.Length];
    using var aes = new AesGcm(wrapKey, 16);
    aes.Decrypt(nonce, cipher, tag, payloadKey);
    return payloadKey.Length > 0;
  } catch (Exception) {
    return false;
  }
}

static string LicenseKey() {
  var fromEnv = Environment.GetEnvironmentVariable("KERN_LICENSE_KEY");
  if (!string.IsNullOrWhiteSpace(fromEnv)) return fromEnv.Trim();
  if (!Console.IsInputRedirected) Console.Write("Enter license: ");
  return (Console.ReadLine() ?? "").Trim();
}
