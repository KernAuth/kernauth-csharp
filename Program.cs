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
if (!features.RootElement.TryGetProperty("payload_key", out var payloadKey)
    || payloadKey.ValueKind != JsonValueKind.String
    || string.IsNullOrEmpty(payloadKey.GetString())) {
  Console.WriteLine("Payload key is missing");
  Environment.Exit(1);
}
// Decrypt the program with this key. Drop it when the heartbeat fails.
Console.WriteLine($"Status: {app.Status}");
Console.WriteLine($"Features: {app.Features}");
Console.WriteLine($"Payload key: {payloadKey.GetString()}");
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

static string LicenseKey() {
  var fromEnv = Environment.GetEnvironmentVariable("KERN_LICENSE_KEY");
  if (!string.IsNullOrWhiteSpace(fromEnv)) return fromEnv.Trim();
  if (!Console.IsInputRedirected) Console.Write("Enter license: ");
  return (Console.ReadLine() ?? "").Trim();
}
