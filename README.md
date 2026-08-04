# Attestation verifier

Server side verification of Android Key Attestation and Apple App Attest, in C#,
written to be read rather than just used.

Every check is a named step that logs a line, so a rejection tells you which
condition failed instead of returning false.

Targets `netstandard2.0` and `net8.0`. The first matters if your server runs .NET
Framework 4.8, which a lot of enterprise .NET still does.

## The problem it solves

An app says "the user passed biometrics". You cannot believe it. A hooking
framework changes that boolean in one line.

The fix is to stop asking the app and start asking the hardware. The device creates
a key inside its secure element, gated on biometrics, and the vendor issues evidence
about that key. The server verifies the evidence, stores the public key, and from
then on every sensitive action requires a signature over a server issued nonce.

Two different proofs, easy to confuse:

| | Attestation | Signature |
|---|---|---|
| Answers | was this key born in real hardware, in my real app | is this the same key, unlocked by biometrics, now |
| When | once, at enrollment | every protected action |
| Verified against | a vendor root certificate | the stored public key |
| This repo | yes | no, that part is a one line ECDSA verify |

## Quick start

```bash
dotnet build tools/VerifyCli/VerifyCli.csproj

dotnet tools/VerifyCli/bin/Debug/net8.0/verify-attestation.dll \
  chain.txt roots/GoogleAttestationRoots.pem <nonce base64> [package] [signing digest base64]
```

Exit code 0 accepted, 1 rejected, 2 usage error.

Pass `-` instead of the nonce to print what is inside the certificate without
checking freshness. Useful while exploring, never in production.

`chain.txt` can be a JSON array, a string with escaped `\n`, comma separated PEM
blocks, or plain PEM. All four turn up in real logs, all four are accepted.

## Android, what gets checked

```
1  chain parsed, at least two certificates
2  trust anchors loaded and not expired, empty value is a hard failure
3  chain ordered leaf first, by issuer and subject, no assumption about length
4  every link verified: each certificate is signed by the next one
5  the walk stops at the first certificate signed by a pinned root
6  validity dates checked, for the certificates in the verified path only
7  extension 1.3.6.1.4.1.11129.2.1.17 present and parseable
8  attestationChallenge equals the nonce the backend issued
9  attestationSecurityLevel is TEE or StrongBox, never Software
10 origin is generated, not imported
11 purpose is SIGN only, algorithm EC P-256, digest SHA-256
12 noAuthRequired absent, userAuthType includes biometrics, authTimeout absent
13 rootOfTrust: bootloader locked, verified boot state Verified
14 package name and signing digest match your configuration
15 public key extracted from the verified leaf
```

Steps 9 to 13 read the hardware enforced list only. Values in the software enforced
list are written by the OS and prove nothing. The one exception is
`attestationApplicationId`, which the keystore daemon fills in rather than the app.

## Three things that trip people up

**The root the device sends is not a trust anchor.** Older devices ship a factory
root whose validity has already lapsed. Standard X.509 path validation rejects the
whole device class. The fix is to drop the last certificate from the request and
build the path to your own pinned copy instead. This is why the code does not use
`X509Chain`.

**Take the public key from the certificate, not from the request body.** Otherwise
an attacker replays somebody else's valid chain together with their own software
generated key. The chain verifies, and you store the attacker's key.

**Chain length and format version both vary.** Across the devices used to develop
this, chains came in at three and four certificates, and the record format ranged from
`attestationVersion 3` (Keymaster 4, an Android 11 handset) to `attestationVersion 300`
(KeyMint 3, an Android 14 handset). Five element chains exist too. Code that assumes
`chain[3]` is the root, or that switches on version 3 alone, breaks on hardware it was
never tested against.

## iOS, and why it is structurally different

Android key attestation describes the signing key, so verifying the chain proves
things about that key directly.

App Attest describes the app and the device. It says nothing about your biometric
key. The two are tied together by the clientDataHash, which the app computes over
the key material and Apple seals into the certificate:

```
clientDataHash = SHA256( challenge || publicKeyPem || deviceId || bundleId )
nonce          = SHA256( authData || clientDataHash )
```

The server recomputes clientDataHash from its own challenge and the public key in
the request. It must never take the value from the request body. Skip that
recomputation and the evidence proves only that the app is genuine, with any key at
all attached to it.

The exact concatenation is a contract between client and server. Change the order or
add a newline on either side and every enrollment fails with a nonce mismatch, which
is a miserable thing to debug. Write it down.

```bash
dotnet tools/VerifyCli/bin/Debug/net8.0/verify-attestation.dll ios \
  input.json roots/AppleAppAttestRoot.pem <teamId.bundleId> <bundleId> [--production]
```

```json
{
  "attestationObjectBase64": "...",
  "appAttestKeyIdBase64":   "...",
  "nonceBase64":            "...",
  "publicKeyPem":           "-----BEGIN PUBLIC KEY-----\n...",
  "deviceId":               "..."
}
```

`appId` is `teamId.bundleId` and is used for the rpIdHash comparison. `bundleId` is
the bundle identifier alone and goes into the clientDataHash. They are different
values and cannot be merged.

App Attest leaf certificates live about three days, so stored samples will be outside
their validity window. The verifier warns rather than rejects, since a stale sample
is a test artefact. A live enrollment arriving with an expired leaf is a different
matter and the calling code should treat it as a failure.

## Enrollment without attestation

Some devices cannot produce usable evidence. Huawei is the common case: SafetyDetect
needs an entitlement that may not be granted, and the keystore chain can terminate at
the AOSP software attestation root, whose private key is published in the Android
source tree.

If the decision is to enrol those devices anyway, the public key has to come from the
request body. `BiometricKeyValidator` does the little that can still be done: confirm
the value is a well formed EC P-256 key and hand back a trust level to store.

```bash
dotnet tools/VerifyCli/bin/Debug/net8.0/verify-attestation.dll key public.pem
```

This is a real reduction in assurance and the output says so. What survives is the
key binding: an attacker still cannot produce a signature over a server nonce without
the private key, so a faked biometric callback authorises nothing. That is usually
the finding you were asked to close in the first place.

## Producing your own test evidence

No sample chains are bundled. Chains carry the package name and signing certificate
digest of whoever generated them, so shipping someone else's is a small privacy leak
and shipping your own is a decision you should make deliberately.

Generating one takes about twenty lines in any Android app:

```kotlin
val challenge = /* the nonce your server issued, base64 decoded */
val spec = KeyGenParameterSpec.Builder("demo_key", KeyProperties.PURPOSE_SIGN)
    .setDigests(KeyProperties.DIGEST_SHA256)
    .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
    .setUserAuthenticationRequired(true)
    .setAttestationChallenge(challenge)
    .apply {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            setInvalidatedByBiometricEnrollment(true)
        }
    }
    .build()

KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")
    .apply { initialize(spec) }
    .generateKeyPair()

val chain = KeyStore.getInstance("AndroidKeyStore")
    .apply { load(null) }
    .getCertificateChain("demo_key")
// write each certificate out as PEM, concatenate, feed to the verifier
```

Then:

```bash
./test.sh path/to/chain.pem <the nonce you used> <your package name>
```

Two things to know before you try. The bootloader has to be locked, otherwise the
secure element downgrades itself to software attestation and the chain will
correctly fail. And no biometric prompt appears during key creation: the prompt comes
later, at the first signature.

## Trust anchors

`roots/` holds the two vendor roots. Both are public downloads, unchanged.

```bash
curl -s https://android.googleapis.com/attestation/root \
  | python3 -c "import json,sys; print('\\n'.join(json.load(sys.stdin)))" \
  > roots/GoogleAttestationRoots.pem

curl -s https://www.apple.com/certificateauthority/Apple_App_Attestation_Root_CA.pem \
  > roots/AppleAppAttestRoot.pem
```

The Google endpoint returns a JSON array rather than PEM, which is easy to paste into
a config field and then wonder why nothing validates.

Both Google roots are needed. The RSA one covers factory provisioned keys on older
devices, the EC one covers Remote Key Provisioning on newer devices. Load one and the
devices covered by the other are rejected.

```
Google root 1  CE:DB:1C:B6:DC:89:6A:E5:EC:79:73:48:BC:E9:28:67:53:C2:B3:8E:E7:1C:E0:FB:E3:4A:9A:12:48:80:0D:FC
Google root 2  6D:9D:B4:CE:6C:5C:0B:29:31:66:D0:89:86:E0:57:74:A8:77:6C:EB:52:5D:9E:43:29:52:0D:E1:2B:A4:BC:C0
Apple root     1C:B9:82:3B:A2:8B:A6:AD:2D:33:A0:06:94:1D:E2:AE:4F:51:3E:F1:D4:E8:31:B9:F7:E0:FA:7B:62:42:C9:32
```

## Not included

Revocation. Roots say who issued a certificate, not whether it is still trusted.
Google publishes a list of compromised attestation keys, currently around 1700
entries, most of them `KEY_COMPROMISE`. Every serial in the chain should be checked
against it:

```
https://android.googleapis.com/attestation/status
```

That is a live HTTP call with its own caching and failure modes, which is why it sits
outside a module that is otherwise pure offline arithmetic. Somebody who extracted a
key from one device can mint valid chains on a laptop forever, and this list is the
only thing that stops them.

Also not included, because they belong to whatever calls this: challenge lookup and
expiry, single use enforcement, lockout counters, and storing the public key.

## Layout

```
src/AttestationVerifier/
  Pem.cs                          tolerant PEM reader
  CertificateChain.cs             ordering, path building, signature verification
  KeyDescription.cs               ASN.1 of the Android attestation extension
  AndroidAttestationVerifier.cs   Android checks, in order
  IosAppAttestVerifier.cs         App Attest, CBOR and the clientDataHash binding
  PublicKeyReader.cs              SubjectPublicKeyInfo to ECDsa, works on .NET Framework
  SubjectPublicKeyInfoBuilder.cs  the reverse, same reason
  BiometricKeyValidator.cs        unattested enrollment fallback
tools/VerifyCli/                  console runner
roots/                            vendor root certificates
```

Around 1900 lines. No dependency injection, no interfaces with one implementation, no
abstract factory. Two NuGet packages, both from Microsoft, both for parsing.

## References

- <https://developer.android.com/privacy-and-security/security-key-attestation>
- <https://developer.android.com/privacy-and-security/security-key-attestation#certificate_status>
- <https://developer.apple.com/documentation/devicecheck/validating-apps-that-connect-to-your-server>
- <https://android.googlesource.com/platform/external/keyattestation/>

## License

MIT.
