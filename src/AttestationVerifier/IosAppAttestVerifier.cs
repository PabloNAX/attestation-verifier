using System;
using System.Collections.Generic;
using System.Formats.Asn1;
using System.Formats.Cbor;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace AttestationVerifier
{
    /// <summary>
    /// Apple App Attest verifier.
    ///
    /// The important difference from Android. Android key attestation describes the
    /// signing key itself, so verifying the chain proves things about that key.
    /// App Attest describes the app and the device, and says nothing about the
    /// biometric key. The link between the two is the clientDataHash, which the app
    /// computes as
    ///
    ///     SHA256(challenge || biometricPublicKeyPem || deviceId || bundleId)
    ///
    /// and Apple binds into the certificate. The server recomputes the same hash from
    /// its own challenge and the public key in the request. If it matches, the App
    /// Attest evidence belongs to that specific biometric key. If the server skipped
    /// this and trusted the clientDataHash sent by the client, the evidence would
    /// prove only that the app is genuine, and any key could be attached to it.
    ///
    ///   attestationObject = {
    ///       fmt:     "apple-appattest",
    ///       attStmt: { x5c: [credCert, intermediate], receipt: bytes },
    ///       authData: bytes }
    ///
    ///   authData = rpIdHash[32] | flags[1] | signCount[4] |
    ///              aaguid[16] | credentialIdLength[2] | credentialId[..] | coseKey
    /// </summary>
    public class IosAppAttestVerifier
    {
        /// <summary>Apple puts the nonce in this certificate extension.</summary>
        private const string NonceExtensionOid = "1.2.840.113635.100.8.2";

        private const string AaguidDevelopment = "appattestdevelop";
        private const string AaguidProduction = "appattest";

        public sealed class Result
        {
            public bool IsValid;
            public string RejectReason = AttestationVerifier.RejectReason.None;
            public string PublicKeyPem = "";
            public string AppId = "";
            public string Environment = "";
            public string Report = "";
        }

        private sealed class Log
        {
            private readonly StringBuilder _sb = new StringBuilder();
            public string Failure;
            public string FailureReason;

            public void Ok(string t) { _sb.AppendLine("[ OK ] " + t); }
            public void Info(string t) { _sb.AppendLine("[    ] " + t); }
            public void Warn(string t) { _sb.AppendLine("[WARN] " + t); }
            public void Fail(string t, string reason)
            {
                _sb.AppendLine("[FAIL] " + t);
                if (Failure == null) { Failure = t; FailureReason = reason; }
            }
            public override string ToString() { return _sb.ToString(); }
        }

        /// <summary>Entry point using out parameters, so low-code hosts can map them to output parameters directly.</summary>
        public void VerifyIosAppAttestation(
            string attestationObjectBase64,
            string appAttestKeyIdBase64,
            string expectedNonceBase64,
            string biometricPublicKeyPem,
            string deviceId,
            string appleRootPem,
            string expectedAppId,
            string expectedBundleId,
            bool requireProduction,
            out bool isValid,
            out string rejectReason,
            out string publicKeyPem,
            out string environment,
            out string report)
        {
            var r = Verify(attestationObjectBase64, appAttestKeyIdBase64, expectedNonceBase64,
                           biometricPublicKeyPem, deviceId, appleRootPem,
                           expectedAppId, expectedBundleId, requireProduction);
            isValid = r.IsValid;
            rejectReason = r.RejectReason;
            publicKeyPem = r.PublicKeyPem;
            environment = r.Environment;
            report = r.Report;
        }

        public Result Verify(
            string attestationObjectBase64,
            string appAttestKeyIdBase64,
            string expectedNonceBase64,
            string biometricPublicKeyPem,
            string deviceId,
            string appleRootPem,
            string expectedAppId,
            string expectedBundleId,
            bool requireProduction)
        {
            var log = new Log();
            var result = new Result();
            result.AppId = expectedAppId ?? "";

            try
            {
                // -------------------------------------------------------------
                // 0. Trust anchor
                // -------------------------------------------------------------
                var roots = Pem.ReadCertificates(appleRootPem)
                               .Select(d => new X509Certificate2(d)).ToList();
                if (roots.Count == 0)
                {
                    log.Fail("trust anchor: AppleAppAttestRoot is empty", RejectReason.ConfigError);
                    return Finish(result, log);
                }
                log.Ok("trust anchor loaded: " + roots[0].Subject);

                // -------------------------------------------------------------
                // 1. Unpack the CBOR attestation object
                // -------------------------------------------------------------
                byte[] authData;
                List<byte[]> x5c;
                bool receiptPresent;
                string format;
                ParseAttestationObject(Pem.DecodeBase64(attestationObjectBase64),
                                       out format, out authData, out x5c, out receiptPresent);

                if (format != "apple-appattest")
                {
                    log.Fail("format: expected apple-appattest, got " + format, RejectReason.AttestationInvalid);
                    return Finish(result, log);
                }
                log.Ok("format: apple-appattest, " + x5c.Count + " certificates, authData " + authData.Length + " bytes");
                if (receiptPresent) log.Info("receipt present, " + "can be used later for fraud metrics");

                // -------------------------------------------------------------
                // 2. Certificate path: credCert -> intermediate -> pinned Apple root
                // -------------------------------------------------------------
                var certs = x5c.Select(d => new X509Certificate2(d)).ToList();
                var ordered = CertificateChain.Order(certs);
                for (int i = 0; i < ordered.Count; i++)
                {
                    log.Info("cert[" + i + "] " + ordered[i].Subject);
                }

                bool anchored = false;
                for (int i = 0; i < ordered.Count; i++)
                {
                    foreach (var root in roots)
                    {
                        if (!CertificateChain.IsIssuedBy(ordered[i], root)) continue;
                        if (!CertificateChain.VerifySignature(ordered[i], root)) continue;
                        anchored = true;
                        break;
                    }
                    if (anchored)
                    {
                        log.Ok("cert[" + i + "] is signed by the pinned Apple root");
                        break;
                    }
                    if (i + 1 >= ordered.Count)
                    {
                        log.Fail("path: chain does not reach the Apple App Attest root", RejectReason.AttestationInvalid);
                        return Finish(result, log);
                    }
                    if (!CertificateChain.VerifySignature(ordered[i], ordered[i + 1]))
                    {
                        log.Fail("path: cert[" + i + "] is not signed by cert[" + (i + 1) + "]",
                                 RejectReason.AttestationInvalid);
                        return Finish(result, log);
                    }
                    log.Ok("link: cert[" + i + "] signed by cert[" + (i + 1) + "]");
                }

                var credCert = ordered[0];
                var now = DateTime.UtcNow;
                if (now > credCert.NotAfter.ToUniversalTime() || now < credCert.NotBefore.ToUniversalTime())
                {
                    // App Attest leaf certificates are short lived, a few days.
                    log.Warn("validity: credCert is outside its validity window, valid " +
                             credCert.NotBefore.ToUniversalTime().ToString("yyyy-MM-dd") + " to " +
                             credCert.NotAfter.ToUniversalTime().ToString("yyyy-MM-dd") +
                             ". Expected for stored test data, not acceptable for a live enrollment");
                }
                else
                {
                    log.Ok("validity: credCert is inside its validity window");
                }

                // -------------------------------------------------------------
                // 3. Rebuild clientDataHash from our own inputs.
                //    Never take it from the request body.
                // -------------------------------------------------------------
                var challenge = Pem.DecodeBase64(expectedNonceBase64);
                if (challenge.Length == 0)
                {
                    log.Fail("nonce: expected nonce is empty", RejectReason.ConfigError);
                    return Finish(result, log);
                }

                byte[] clientDataHash;
                using (var sha = SHA256.Create())
                {
                    var material = new List<byte>();
                    material.AddRange(challenge);
                    material.AddRange(Encoding.UTF8.GetBytes(biometricPublicKeyPem ?? ""));
                    material.AddRange(Encoding.UTF8.GetBytes(deviceId ?? ""));
                    material.AddRange(Encoding.UTF8.GetBytes(expectedBundleId ?? ""));
                    clientDataHash = sha.ComputeHash(material.ToArray());
                }
                log.Info("clientDataHash recomputed from challenge, public key, deviceId and bundleId");

                // -------------------------------------------------------------
                // 4. nonce = SHA256(authData || clientDataHash), and it must be the
                //    value Apple sealed into the certificate extension.
                // -------------------------------------------------------------
                byte[] expectedInCert;
                using (var sha = SHA256.Create())
                {
                    var material = new byte[authData.Length + clientDataHash.Length];
                    Buffer.BlockCopy(authData, 0, material, 0, authData.Length);
                    Buffer.BlockCopy(clientDataHash, 0, material, authData.Length, clientDataHash.Length);
                    expectedInCert = sha.ComputeHash(material);
                }

                var nonceInCert = ReadNonceExtension(credCert);
                if (nonceInCert == null)
                {
                    log.Fail("extension " + NonceExtensionOid + " is missing from credCert",
                             RejectReason.AttestationInvalid);
                    return Finish(result, log);
                }
                if (!ConstantTimeEquals(nonceInCert, expectedInCert))
                {
                    log.Fail("nonce: certificate carries " + Pem.ToHex(nonceInCert) +
                             ", recomputed " + Pem.ToHex(expectedInCert) +
                             ". Either the challenge, the public key, the deviceId or the bundleId differs",
                             RejectReason.NonceMismatch);
                    return Finish(result, log);
                }
                log.Ok("nonce matches, the attestation is bound to this challenge and this biometric key");

                // -------------------------------------------------------------
                // 5. keyId must be the SHA256 of the credCert public key
                // -------------------------------------------------------------
                var credPoint = credCert.PublicKey.EncodedKeyValue.RawData;
                byte[] computedKeyId;
                using (var sha = SHA256.Create()) computedKeyId = sha.ComputeHash(credPoint);

                var claimedKeyId = Pem.DecodeBase64(appAttestKeyIdBase64);
                if (claimedKeyId.Length == 0)
                {
                    log.Fail("keyId: not supplied. iOS enrollment must send appAttestKeyId",
                             RejectReason.AttestationInvalid);
                    return Finish(result, log);
                }
                if (!ConstantTimeEquals(claimedKeyId, computedKeyId))
                {
                    log.Fail("keyId: request says " + Convert.ToBase64String(claimedKeyId) +
                             ", credCert hashes to " + Convert.ToBase64String(computedKeyId),
                             RejectReason.AttestationInvalid);
                    return Finish(result, log);
                }
                log.Ok("keyId matches the credCert public key");

                // -------------------------------------------------------------
                // 6. authData fields
                // -------------------------------------------------------------
                var rpIdHash = new byte[32];
                Buffer.BlockCopy(authData, 0, rpIdHash, 0, 32);

                uint signCount = (uint)((authData[33] << 24) | (authData[34] << 16) |
                                        (authData[35] << 8) | authData[36]);

                var aaguid = new byte[16];
                Buffer.BlockCopy(authData, 37, aaguid, 0, 16);
                var aaguidText = Encoding.ASCII.GetString(aaguid).TrimEnd('\0');

                int credIdLength = (authData[53] << 8) | authData[54];
                var credentialId = new byte[credIdLength];
                Buffer.BlockCopy(authData, 55, credentialId, 0, credIdLength);

                if (string.IsNullOrWhiteSpace(expectedAppId))
                {
                    log.Warn("appId: not configured, rpIdHash check skipped. Configure teamId.bundleId");
                }
                else
                {
                    byte[] expectedRpId;
                    using (var sha = SHA256.Create())
                        expectedRpId = sha.ComputeHash(Encoding.UTF8.GetBytes(expectedAppId));

                    if (!ConstantTimeEquals(rpIdHash, expectedRpId))
                    {
                        log.Fail("appId: rpIdHash does not match SHA256(" + expectedAppId + ")",
                                 RejectReason.AttestationInvalid);
                        return Finish(result, log);
                    }
                    log.Ok("appId: rpIdHash matches " + expectedAppId);
                }

                if (signCount != 0)
                {
                    log.Fail("signCount: expected 0 for an attestation, got " + signCount,
                             RejectReason.AttestationInvalid);
                    return Finish(result, log);
                }
                log.Ok("signCount: 0, this is a fresh attestation and not a replayed assertion");

                result.Environment = aaguidText == AaguidDevelopment ? "development"
                                   : aaguidText == AaguidProduction ? "production"
                                   : "unknown(" + aaguidText + ")";

                if (requireProduction && aaguidText != AaguidProduction)
                {
                    log.Fail("environment: production required, attestation is " + result.Environment,
                             RejectReason.AttestationInvalid);
                    return Finish(result, log);
                }
                log.Ok("environment: " + result.Environment);
                if (result.Environment == "development")
                {
                    log.Warn("this attestation came from the App Attest sandbox. Production must reject it");
                }

                if (!ConstantTimeEquals(credentialId, claimedKeyId))
                {
                    log.Fail("credentialId inside authData does not equal the supplied keyId",
                             RejectReason.AttestationInvalid);
                    return Finish(result, log);
                }
                log.Ok("credentialId inside authData equals the keyId");

                // -------------------------------------------------------------
                // 7. The key we store is the biometric key from the request, which
                //    step 4 has just tied to this attestation. The App Attest key is
                //    a different key and is not used for signing challenges.
                // -------------------------------------------------------------
                result.PublicKeyPem = biometricPublicKeyPem ?? "";
                log.Ok("biometric public key is bound to this attestation and can be stored");
                log.Info("App Attest receipt was not sent to Apple. That is a separate optional call");

                result.IsValid = true;
                return Finish(result, log);
            }
            catch (Exception ex)
            {
                log.Fail("unexpected error: " + ex.GetType().Name + ": " + ex.Message,
                         RejectReason.AttestationInvalid);
                return Finish(result, log);
            }
        }

        // ---------------------------------------------------------------------

        private static void ParseAttestationObject(
            byte[] cbor, out string format, out byte[] authData, out List<byte[]> x5c, out bool receiptPresent)
        {
            format = null;
            authData = null;
            x5c = new List<byte[]>();
            receiptPresent = false;

            var reader = new CborReader(cbor, CborConformanceMode.Lax);
            int? count = reader.ReadStartMap();

            while (reader.PeekState() != CborReaderState.EndMap)
            {
                var key = reader.ReadTextString();
                switch (key)
                {
                    case "fmt":
                        format = reader.ReadTextString();
                        break;
                    case "authData":
                        authData = reader.ReadByteString();
                        break;
                    case "attStmt":
                        reader.ReadStartMap();
                        while (reader.PeekState() != CborReaderState.EndMap)
                        {
                            var inner = reader.ReadTextString();
                            if (inner == "x5c")
                            {
                                reader.ReadStartArray();
                                while (reader.PeekState() != CborReaderState.EndArray)
                                {
                                    x5c.Add(reader.ReadByteString());
                                }
                                reader.ReadEndArray();
                            }
                            else if (inner == "receipt")
                            {
                                reader.ReadByteString();
                                receiptPresent = true;
                            }
                            else
                            {
                                reader.SkipValue();
                            }
                        }
                        reader.ReadEndMap();
                        break;
                    default:
                        reader.SkipValue();
                        break;
                }
            }
            reader.ReadEndMap();
        }

        /// <summary>
        /// The extension value is SEQUENCE { [1] EXPLICIT OCTET STRING }.
        /// Read it tolerantly: return the first 32 byte octet string found.
        /// </summary>
        private static byte[] ReadNonceExtension(X509Certificate2 cert)
        {
            foreach (var ext in cert.Extensions)
            {
                if (ext.Oid == null || ext.Oid.Value != NonceExtensionOid) continue;

                try
                {
                    var reader = new AsnReader(ext.RawData, AsnEncodingRules.DER);
                    if (reader.PeekTag() == Asn1Tag.PrimitiveOctetString)
                    {
                        reader = new AsnReader(reader.ReadOctetString(), AsnEncodingRules.DER);
                    }
                    var seq = reader.ReadSequence();
                    var tag = seq.PeekTag();
                    var item = seq.ReadSequence(tag);
                    return item.ReadOctetString();
                }
                catch
                {
                    // fall back to a raw scan for a 32 byte octet string
                    var raw = ext.RawData;
                    for (int i = 0; i + 34 <= raw.Length; i++)
                    {
                        if (raw[i] == 0x04 && raw[i + 1] == 0x20)
                        {
                            var value = new byte[32];
                            Buffer.BlockCopy(raw, i + 2, value, 0, 32);
                            return value;
                        }
                    }
                }
            }
            return null;
        }

        private static Result Finish(Result result, Log log)
        {
            if (log.Failure != null)
            {
                result.IsValid = false;
                result.RejectReason = log.FailureReason;
            }
            var footer = result.IsValid
                ? "RESULT: accepted"
                : "RESULT: rejected, " + result.RejectReason + " (" + log.Failure + ")";
            result.Report = log.ToString() + footer;
            return result;
        }

        private static bool ConstantTimeEquals(byte[] a, byte[] b)
        {
            if (a == null || b == null || a.Length != b.Length) return false;
            int diff = 0;
            for (int i = 0; i < a.Length; i++) diff |= a[i] ^ b[i];
            return diff == 0;
        }
    }
}
