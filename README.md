# KernAuth C# example

Protocol example for .NET 8. This is not the official SDK. The official client is the C++ SDK. This file calls validate and checks the Ed25519 signature with BouncyCastle.

## Add it

Paste the public app ID, key ID, and public key from Developers over the placeholders in `Program.cs`.

```
dotnet run -- --test-vectors
```

Run with `KERN_LICENSE_KEY` and `KERN_INSTALLATION_ID` set. Persist one installation ID per device.

## Instance

```csharp
var app = new KernAuth(
    "https://api.kernauth.com",
    "__PUBLIC_APP_ID__",
    "__KEY_ID__",
    "__PUBLIC_KEY__");
```

## Validate

```csharp
if (!await app.Validate(license, installation)) {
    throw new Exception(app.Message);
}
```

A patched program can still skip the check. These examples do not add anti-debug or anti-VM code.

Documentation: https://kernauth.apidog.io
