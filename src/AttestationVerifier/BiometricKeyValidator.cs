using System;
using System.Security.Cryptography;

namespace AttestationVerifier
{
    /// <summary>
    /// Enrollment without attestation.
    ///
    /// On Android and iOS the public key comes out of a verified attestation, so the
    /// server never has to trust the request body. On Huawei that evidence does not
    /// exist: SafetyDetect returns 6004 PERMISSION_NOT_EXIST and the keystore chain
    /// terminates at the AOSP software attestation root, whose private key is public.
    ///
    /// If the decision is to enrol Huawei devices anyway, the public key has to be
    /// taken from the request body. That is a real reduction in assurance and should
    /// be recorded as such, not hidden. This class does the little that can still be
    /// done: confirm the value is a well formed EC P-256 public key and hand back a
    /// canonical form to store.
    ///
    /// What this does NOT prove, and no amount of parsing can:
    ///   that the private key lives in secure hardware
    ///   that the private key is on that device at all
    ///   that the device is not rooted
    ///
    /// What survives without attestation: the key binding itself. An attacker cannot
    /// produce a signature over a server issued nonce without the private key, so a
    /// faked biometric callback still does not authorise anything. That is the part
    /// the security finding actually asked for.
    /// </summary>
    public class BiometricKeyValidator
    {
        /// <summary>Trust level to store alongside the key, so risk policy can use it later.</summary>
        public const string TrustAttested = "HARDWARE_ATTESTED";
        public const string TrustUnattested = "SELF_REPORTED";

        /// <summary>Entry point using out parameters, so low-code hosts can map them to output parameters directly.</summary>
        public void ValidateBiometricPublicKey(
            string publicKeyPem,
            out bool isValid,
            out string rejectReason,
            out string curve,
            out string trustLevel,
            out string report)
        {
            isValid = false;
            rejectReason = RejectReason.AttestationInvalid;
            curve = "";
            trustLevel = TrustUnattested;

            if (string.IsNullOrWhiteSpace(publicKeyPem))
            {
                report = "[FAIL] public key: empty\nRESULT: rejected";
                return;
            }

            ECDsa key;
            try
            {
                key = PublicKeyReader.ReadEcPublicKey(publicKeyPem);
            }
            catch (Exception ex)
            {
                report = "[FAIL] public key: cannot parse SubjectPublicKeyInfo: " + ex.Message +
                         "\nRESULT: rejected";
                return;
            }

            using (key)
            {
                curve = "P-" + key.KeySize;

                // The app is configured to create EC P-256 keys. Anything else means the
                // client is not the build we think it is, or the value was substituted.
                if (key.KeySize != 256)
                {
                    report = "[FAIL] public key: expected EC P-256, got " + curve +
                             "\nRESULT: rejected";
                    return;
                }
            }

            isValid = true;
            rejectReason = RejectReason.None;
            trustLevel = TrustUnattested;
            report =
                "[ OK ] public key parses as EC P-256\n" +
                "[WARN] no attestation was verified for this key\n" +
                "[WARN] hardware backing, device binding and root status are unknown\n" +
                "[    ] store with trustLevel " + TrustUnattested + " and apply risk policy\n" +
                "RESULT: accepted, unattested";
        }
    }
}
