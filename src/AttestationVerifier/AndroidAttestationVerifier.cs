using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace AttestationVerifier
{
    /// <summary>
    /// Reject reasons. These match the enum the mobile app already ships in
    /// biometric_crypto_enums.dart, so the value can go straight into the response.
    /// </summary>
    public static class RejectReason
    {
        public const string None = "";
        public const string AttestationInvalid = "ATTESTATION_INVALID";
        public const string NotHardwareBacked = "NOT_HARDWARE_BACKED";
        public const string NotBiometricGated = "NOT_BIOMETRIC_GATED";
        public const string NonceMismatch = "NONCE_MISMATCH";
        public const string ConfigError = "CONFIG_ERROR";
    }

    /// <summary>
    /// Android Key Attestation verifier.
    ///
    /// Two questions are answered, in this order:
    ///   1. Is the evidence genuine?  Certificate path from the leaf to a pinned
    ///      Google root, every signature checked.
    ///   2. What does the evidence say? Fields inside the leaf, read from the
    ///      hardware enforced list.
    ///
    /// Not covered here, because it needs a live HTTP call and belongs to the caller:
    ///   revocation, via https://android.googleapis.com/attestation/status
    ///   challenge freshness, which is a lookup in your own database
    /// </summary>
    public class AndroidAttestationVerifier
    {
        /// <summary>
        /// Entry point using out parameters, so low-code hosts can map them to output parameters directly.
        /// Integration Studio will expose this as VerifyAndroidAttestation with
        /// the out parameters becoming output parameters of the server action.
        /// </summary>
        public void VerifyAndroidAttestation(
            string certChainPem,
            string expectedNonceBase64,
            string googleRootsPem,
            string expectedPackageName,
            string expectedSigningDigestBase64,
            bool requireStrongBox,
            out bool isValid,
            out string rejectReason,
            out string publicKeyPem,
            out string securityLevel,
            out string packageName,
            out int osVersion,
            out int osPatchLevel,
            out string report)
        {
            var r = Verify(
                certChainPem,
                expectedNonceBase64,
                googleRootsPem,
                expectedPackageName,
                expectedSigningDigestBase64,
                requireStrongBox);

            isValid = r.IsValid;
            rejectReason = r.RejectReason;
            publicKeyPem = r.PublicKeyPem;
            securityLevel = r.SecurityLevel;
            packageName = r.PackageName;
            osVersion = r.OsVersion;
            osPatchLevel = r.OsPatchLevel;
            report = r.Report;
        }

        public sealed class Result
        {
            public bool IsValid;
            public string RejectReason = AttestationVerifier.RejectReason.None;
            public string PublicKeyPem = "";
            public string SecurityLevel = "";
            public string PackageName = "";
            public string SigningDigestBase64 = "";
            public int OsVersion;
            public int OsPatchLevel;
            public string Report = "";
        }

        private sealed class Log
        {
            private readonly StringBuilder _sb = new StringBuilder();
            public string Failure;
            public string FailureReason;

            public void Ok(string text) { _sb.AppendLine("[ OK ] " + text); }
            public void Info(string text) { _sb.AppendLine("[    ] " + text); }
            public void Warn(string text) { _sb.AppendLine("[WARN] " + text); }

            public void Fail(string text, string reason)
            {
                _sb.AppendLine("[FAIL] " + text);
                if (Failure == null) { Failure = text; FailureReason = reason; }
            }

            public override string ToString() { return _sb.ToString(); }
        }

        public Result Verify(
            string certChainPem,
            string expectedNonceBase64,
            string googleRootsPem,
            string expectedPackageName,
            string expectedSigningDigestBase64,
            bool requireStrongBox)
        {
            var log = new Log();
            var result = new Result();

            try
            {
                // -------------------------------------------------------------
                // 0. Load inputs
                // -------------------------------------------------------------
                var chainCerts = LoadCertificates(certChainPem);
                if (chainCerts.Count < 2)
                {
                    log.Fail("chain: expected at least 2 certificates, got " + chainCerts.Count,
                             RejectReason.AttestationInvalid);
                    return Finish(result, log);
                }
                log.Ok("chain parsed: " + chainCerts.Count + " certificates");

                var roots = LoadCertificates(googleRootsPem);
                if (roots.Count == 0)
                {
                    // Never continue without an anchor. An empty roots value must be a
                    // hard failure, otherwise any self signed chain would be accepted.
                    log.Fail("trust anchors: GoogleAttestationRoots is empty", RejectReason.ConfigError);
                    return Finish(result, log);
                }
                log.Ok("trust anchors loaded: " + roots.Count + " root certificates");
                foreach (var root in roots)
                {
                    if (DateTime.UtcNow > root.NotAfter.ToUniversalTime())
                    {
                        log.Fail("trust anchor expired: " + root.Subject + " on " + root.NotAfter.ToUniversalTime().ToString("yyyy-MM-dd"),
                                 RejectReason.ConfigError);
                        return Finish(result, log);
                    }
                    log.Info("anchor " + Short(root.Subject) + " valid until " + root.NotAfter.ToUniversalTime().ToString("yyyy-MM-dd"));
                }

                var expectedNonce = Pem.DecodeBase64(expectedNonceBase64);

                // -------------------------------------------------------------
                // 1. Order the chain, leaf first
                // -------------------------------------------------------------
                var ordered = CertificateChain.Order(chainCerts);
                for (int i = 0; i < ordered.Count; i++)
                {
                    log.Info("cert[" + i + "] " + Short(ordered[i].Subject) + "  issued by  " + Short(ordered[i].Issuer));
                }

                // -------------------------------------------------------------
                // 2. Walk the path until a pinned root signs the current certificate.
                //
                //    The last certificate the device sends is deliberately not used as
                //    an anchor. Older devices ship an expired factory root copy, and
                //    trusting the phone's own copy of the root would defeat the purpose.
                // -------------------------------------------------------------
                int anchorIndex = -1;
                X509Certificate2 anchorRoot = null;

                for (int i = 0; i < ordered.Count; i++)
                {
                    var current = ordered[i];

                    foreach (var root in roots)
                    {
                        if (!CertificateChain.IsIssuedBy(current, root)) continue;
                        if (!CertificateChain.VerifySignature(current, root)) continue;
                        anchorIndex = i;
                        anchorRoot = root;
                        break;
                    }
                    if (anchorIndex >= 0)
                    {
                        log.Ok("cert[" + i + "] is signed by pinned root " + Short(anchorRoot.Subject));
                        break;
                    }

                    if (i + 1 >= ordered.Count)
                    {
                        log.Fail("path: chain does not reach any pinned root", RejectReason.AttestationInvalid);
                        return Finish(result, log);
                    }

                    if (!CertificateChain.VerifySignature(current, ordered[i + 1]))
                    {
                        log.Fail("path: cert[" + i + "] is not signed by cert[" + (i + 1) + "]",
                                 RejectReason.AttestationInvalid);
                        return Finish(result, log);
                    }
                    log.Ok("link: cert[" + i + "] signed by cert[" + (i + 1) + "]");
                }

                if (anchorIndex < ordered.Count - 1)
                {
                    log.Info("ignored " + (ordered.Count - 1 - anchorIndex) +
                             " certificate(s) above the anchor, including the root copy sent by the device");
                }

                // -------------------------------------------------------------
                // 3. Validity dates, for the certificates actually used.
                //    The root copy sent by the device is not among them, on purpose.
                // -------------------------------------------------------------
                var now = DateTime.UtcNow;
                for (int i = 0; i <= anchorIndex; i++)
                {
                    var c = ordered[i];
                    if (now > c.NotAfter.ToUniversalTime())
                    {
                        log.Fail("validity: cert[" + i + "] expired on " + c.NotAfter.ToUniversalTime().ToString("yyyy-MM-dd"),
                                 RejectReason.AttestationInvalid);
                        return Finish(result, log);
                    }
                    if (now < c.NotBefore.ToUniversalTime())
                    {
                        log.Fail("validity: cert[" + i + "] not valid before " + c.NotBefore.ToUniversalTime().ToString("yyyy-MM-dd"),
                                 RejectReason.AttestationInvalid);
                        return Finish(result, log);
                    }
                }
                log.Ok("validity: certificates in the verified path are within their validity period");

                // -------------------------------------------------------------
                // 4. Read the attestation extension from the leaf
                // -------------------------------------------------------------
                var leaf = ordered[0];
                var extension = CertificateChain.FindAttestationExtension(leaf);
                if (extension == null)
                {
                    log.Fail("extension " + CertificateChain.AttestationExtensionOid + " is missing from the leaf",
                             RejectReason.AttestationInvalid);
                    return Finish(result, log);
                }
                log.Ok("extension " + CertificateChain.AttestationExtensionOid + " found");

                KeyDescription kd;
                try
                {
                    kd = KeyDescription.Parse(extension);
                }
                catch (Exception ex)
                {
                    log.Fail("extension: cannot parse KeyDescription: " + ex.Message, RejectReason.AttestationInvalid);
                    return Finish(result, log);
                }

                var tee = kd.TeeEnforced;
                var sw = kd.SoftwareEnforced;

                result.SecurityLevel = KeyDescription.SecurityLevelName(kd.AttestationSecurityLevel);
                result.PackageName = sw.PackageName ?? tee.PackageName ?? "";
                // Reported so a new environment can be configured by running one real
                // attestation and reading the value, instead of guessing which signing
                // certificate the store used.
                if (sw.SigningDigests.Count > 0)
                {
                    result.SigningDigestBase64 = Convert.ToBase64String(sw.SigningDigests[0]);
                }
                result.OsVersion = tee.OsVersion ?? 0;
                result.OsPatchLevel = tee.OsPatchLevel ?? 0;

                log.Info("attestationVersion " + kd.AttestationVersion +
                         ", keymasterVersion " + kd.KeymasterVersion +
                         ", securityLevel " + result.SecurityLevel);
                if (tee.OsVersion.HasValue || tee.OsPatchLevel.HasValue)
                {
                    log.Info("osVersion " + result.OsVersion + ", osPatchLevel " + result.OsPatchLevel);
                }

                // -------------------------------------------------------------
                // 5. Nonce. This is what makes the evidence one time.
                // -------------------------------------------------------------
                if (expectedNonce.Length == 0)
                {
                    log.Fail("nonce: expected nonce is empty", RejectReason.ConfigError);
                    return Finish(result, log);
                }
                if (!ConstantTimeEquals(kd.AttestationChallenge, expectedNonce))
                {
                    log.Fail("nonce: expected " + Convert.ToBase64String(expectedNonce) +
                             ", certificate contains " + Convert.ToBase64String(kd.AttestationChallenge ?? new byte[0]),
                             RejectReason.NonceMismatch);
                    return Finish(result, log);
                }
                log.Ok("nonce matches: " + Convert.ToBase64String(expectedNonce));

                // -------------------------------------------------------------
                // 6. Hardware backing
                // -------------------------------------------------------------
                if (kd.AttestationSecurityLevel == 0)
                {
                    log.Fail("securityLevel: Software, the key is not hardware backed", RejectReason.NotHardwareBacked);
                    return Finish(result, log);
                }
                if (requireStrongBox && kd.AttestationSecurityLevel != 2)
                {
                    log.Fail("securityLevel: StrongBox required, device provides " + result.SecurityLevel,
                             RejectReason.NotHardwareBacked);
                    return Finish(result, log);
                }
                log.Ok("securityLevel: " + result.SecurityLevel);
                if (kd.AttestationSecurityLevel == 1 && !requireStrongBox)
                {
                    log.Info("StrongBox absent, accepted. Requiring it would reject mid range and older devices");
                }

                if (tee.Origin.HasValue && tee.Origin.Value != AuthorizationList.OriginGenerated)
                {
                    log.Fail("origin: key was imported, not generated inside the secure hardware",
                             RejectReason.NotHardwareBacked);
                    return Finish(result, log);
                }
                log.Ok("origin: generated inside the secure hardware");

                // -------------------------------------------------------------
                // 7. Key properties, read from the hardware enforced list only
                // -------------------------------------------------------------
                if (tee.Purpose.Count == 0)
                {
                    log.Fail("purpose: absent from the hardware enforced list", RejectReason.NotHardwareBacked);
                    return Finish(result, log);
                }
                if (tee.Purpose.Count != 1 || tee.Purpose[0] != AuthorizationList.PurposeSign)
                {
                    log.Fail("purpose: expected SIGN only, got [" + string.Join(",", tee.Purpose) + "]",
                             RejectReason.AttestationInvalid);
                    return Finish(result, log);
                }
                log.Ok("purpose: SIGN only");

                if (tee.Algorithm != AuthorizationList.AlgorithmEc || tee.KeySize != 256 ||
                    (tee.EcCurve.HasValue && tee.EcCurve.Value != AuthorizationList.CurveP256))
                {
                    log.Fail("algorithm: expected EC P-256, got algorithm=" + tee.Algorithm +
                             " keySize=" + tee.KeySize + " curve=" + tee.EcCurve,
                             RejectReason.AttestationInvalid);
                    return Finish(result, log);
                }
                log.Ok("algorithm: EC P-256");

                if (!tee.Digest.Contains(AuthorizationList.DigestSha256))
                {
                    log.Fail("digest: SHA-256 not allowed for this key", RejectReason.AttestationInvalid);
                    return Finish(result, log);
                }
                log.Ok("digest: SHA-256");

                // -------------------------------------------------------------
                // 8. Biometric gating. Three conditions, all in the hardware list.
                // -------------------------------------------------------------
                if (tee.NoAuthRequired)
                {
                    log.Fail("auth: noAuthRequired is present, the key opens without biometrics",
                             RejectReason.NotBiometricGated);
                    return Finish(result, log);
                }
                log.Ok("auth: noAuthRequired absent, user authentication is required");

                if (!tee.UserAuthType.HasValue ||
                    (tee.UserAuthType.Value & AuthorizationList.AuthTypeFingerprint) == 0)
                {
                    log.Fail("auth: userAuthType does not include biometrics, value " + tee.UserAuthType,
                             RejectReason.NotBiometricGated);
                    return Finish(result, log);
                }
                log.Ok("auth: userAuthType includes biometrics");

                if (tee.AuthTimeout.HasValue && tee.AuthTimeout.Value != 0)
                {
                    log.Fail("auth: authTimeout is " + tee.AuthTimeout.Value +
                             " seconds, so one prompt would authorise several operations",
                             RejectReason.NotBiometricGated);
                    return Finish(result, log);
                }
                log.Ok("auth: no timeout, every signature needs its own prompt");

                // -------------------------------------------------------------
                // 9. Device state
                // -------------------------------------------------------------
                if (tee.RootOfTrust == null)
                {
                    log.Fail("rootOfTrust: absent from the hardware enforced list", RejectReason.NotHardwareBacked);
                    return Finish(result, log);
                }
                if (!tee.RootOfTrust.DeviceLocked)
                {
                    log.Fail("rootOfTrust: bootloader is unlocked", RejectReason.NotHardwareBacked);
                    return Finish(result, log);
                }
                log.Ok("rootOfTrust: bootloader locked");

                if (tee.RootOfTrust.VerifiedBootState != RootOfTrust.StateVerified)
                {
                    log.Fail("rootOfTrust: verified boot state is " +
                             RootOfTrust.StateName(tee.RootOfTrust.VerifiedBootState),
                             RejectReason.NotHardwareBacked);
                    return Finish(result, log);
                }
                log.Ok("rootOfTrust: verified boot state is Verified");

                // -------------------------------------------------------------
                // 10. Application identity. Blocks a repackaged build from enrolling.
                // -------------------------------------------------------------
                if (string.IsNullOrWhiteSpace(expectedPackageName))
                {
                    log.Warn("package: no expected package configured, check skipped. Configure this before production");
                }
                else if (!string.Equals(result.PackageName, expectedPackageName, StringComparison.Ordinal))
                {
                    log.Fail("package: expected " + expectedPackageName + ", certificate says " + result.PackageName,
                             RejectReason.AttestationInvalid);
                    return Finish(result, log);
                }
                else
                {
                    log.Ok("package: " + result.PackageName);
                }

                if (string.IsNullOrWhiteSpace(expectedSigningDigestBase64))
                {
                    log.Warn("signing digest: not configured, check skipped. Configure the release digest before production");
                }
                else
                {
                    var expectedDigest = Pem.DecodeBase64(expectedSigningDigestBase64);
                    var found = sw.SigningDigests.Any(d => ConstantTimeEquals(d, expectedDigest));
                    if (!found)
                    {
                        var seen = string.Join(", ", sw.SigningDigests.Select(d => Convert.ToBase64String(d)));
                        log.Fail("signing digest: expected " + Convert.ToBase64String(expectedDigest) +
                                 ", certificate carries [" + seen + "]",
                                 RejectReason.AttestationInvalid);
                        return Finish(result, log);
                    }
                    log.Ok("signing digest matches the configured build");
                }

                // -------------------------------------------------------------
                // 11. The public key. Taken from the verified leaf, never from the
                //     request body. Otherwise an attacker replays somebody else's
                //     valid chain together with their own software key.
                // -------------------------------------------------------------
                result.PublicKeyPem = Pem.WritePublicKey(leaf.PublicKey.EncodedKeyValue == null
                    ? new byte[0]
                    : ExportSubjectPublicKeyInfo(leaf));
                log.Ok("public key extracted from the leaf certificate");

                log.Info("revocation was not checked here. Query android.googleapis.com/attestation/status " +
                         "for leaf serial " + leaf.SerialNumber);

                result.IsValid = true;
                return Finish(result, log);
            }
            catch (Exception ex)
            {
                log.Fail("unexpected error: " + ex.GetType().Name + ": " + ex.Message, RejectReason.AttestationInvalid);
                return Finish(result, log);
            }
        }

        // -------------------------------------------------------------------------

        private static Result Finish(Result result, Log log)
        {
            if (log.Failure != null)
            {
                result.IsValid = false;
                result.RejectReason = log.FailureReason;
            }
            else if (result.IsValid)
            {
                result.RejectReason = RejectReason.None;
            }

            var footer = result.IsValid
                ? "RESULT: accepted"
                : "RESULT: rejected, " + result.RejectReason + " (" + log.Failure + ")";
            result.Report = log.ToString() + footer;
            return result;
        }

        private static List<X509Certificate2> LoadCertificates(string pem)
        {
            var list = new List<X509Certificate2>();
            foreach (var der in Pem.ReadCertificates(pem))
            {
                list.Add(new X509Certificate2(der));
            }
            return list;
        }

        private static byte[] ExportSubjectPublicKeyInfo(X509Certificate2 cert)
        {
#if NETSTANDARD2_0
            // .NET Framework has no ExportSubjectPublicKeyInfo, so rebuild the
            // SubjectPublicKeyInfo from the algorithm and the key bits.
            return SubjectPublicKeyInfoBuilder.Build(cert);
#else
            using (var ecdsa = cert.GetECDsaPublicKey())
            {
                if (ecdsa != null) return ecdsa.ExportSubjectPublicKeyInfo();
            }
            using (var rsa = cert.GetRSAPublicKey())
            {
                if (rsa != null) return rsa.ExportSubjectPublicKeyInfo();
            }
            return SubjectPublicKeyInfoBuilder.Build(cert);
#endif
        }

        private static bool ConstantTimeEquals(byte[] a, byte[] b)
        {
            if (a == null || b == null) return false;
            if (a.Length != b.Length) return false;
            int diff = 0;
            for (int i = 0; i < a.Length; i++) diff |= a[i] ^ b[i];
            return diff == 0;
        }

        private static string Short(string distinguishedName)
        {
            if (string.IsNullOrEmpty(distinguishedName)) return "";
            return distinguishedName.Replace("\r", " ").Replace("\n", " ");
        }
    }
}
