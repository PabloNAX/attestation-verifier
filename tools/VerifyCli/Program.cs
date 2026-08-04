using System;
using System.IO;
using AttestationVerifier;

namespace AttestationVerifier.Cli
{
    /// <summary>
    /// Test runner. Same code path a server would call, driven from the shell.
    /// </summary>
    internal static class Program
    {
        private static int Main(string[] args)
        {
            if (args.Length > 0 && args[0] == "ios") return RunIos(args);
            if (args.Length > 0 && args[0] == "key") return RunKey(args);

            if (args.Length < 3)
            {
                Console.WriteLine("usage:");
                Console.WriteLine();
                Console.WriteLine("  android key attestation");
                Console.WriteLine("    verify-attestation <chain.txt> <roots.pem> <nonceBase64|->");
                Console.WriteLine("                       [package] [signingDigestBase64] [--strongbox]");
                Console.WriteLine();
                Console.WriteLine("  apple app attest");
                Console.WriteLine("    verify-attestation ios <input.json> <AppleAppAttestRoot.pem>");
                Console.WriteLine("                       <teamId.bundleId> <bundleId> [--production]");
                Console.WriteLine();
                Console.WriteLine("  unattested enrollment, public key only");
                Console.WriteLine("    verify-attestation key <publicKey.pem>");
                Console.WriteLine();
                Console.WriteLine("  chain.txt   whatever the app or the server logged: JSON array,");
                Console.WriteLine("              escaped \\n, comma separated or plain PEM, all accepted");
                Console.WriteLine("  roots.pem   the pinned vendor roots, see roots/");
                Console.WriteLine("  nonce       base64 nonce the server issued, or - to read it out of");
                Console.WriteLine("              the certificate instead of checking it");
                Console.WriteLine();
                Console.WriteLine("exit codes: 0 accepted, 1 rejected, 2 usage error");
                return 2;
            }

            var chainPath = args[0];
            var rootsPath = args[1];
            var nonceArg = args[2];
            var package = args.Length > 3 ? args[3] : "";
            var digest = args.Length > 4 ? args[4] : "";
            var requireStrongBox = Array.IndexOf(args, "--strongbox") >= 0;

            if (!File.Exists(chainPath)) { Console.Error.WriteLine("no such file: " + chainPath); return 2; }
            if (!File.Exists(rootsPath)) { Console.Error.WriteLine("no such file: " + rootsPath); return 2; }

            var chain = File.ReadAllText(chainPath);
            var roots = File.ReadAllText(rootsPath);

            var nonce = nonceArg;
            if (nonceArg == "-")
            {
                nonce = ReadNonceFromChain(chain);
                if (nonce == null)
                {
                    Console.Error.WriteLine("could not read the challenge out of the leaf certificate");
                    return 2;
                }
                Console.WriteLine("nonce taken from the certificate itself, freshness NOT verified: " + nonce);
                Console.WriteLine();
            }

            var verifier = new AndroidAttestationVerifier();
            var result = verifier.Verify(chain, nonce, roots, package, digest, requireStrongBox);

            Console.WriteLine(result.Report);
            Console.WriteLine();

            if (result.IsValid)
            {
                Console.WriteLine("securityLevel : " + result.SecurityLevel);
                Console.WriteLine("package       : " + result.PackageName);
                Console.WriteLine("signingDigest : " + result.SigningDigestBase64);
                Console.WriteLine("osVersion     : " + result.OsVersion);
                Console.WriteLine("osPatchLevel  : " + result.OsPatchLevel);
                Console.WriteLine();
                Console.WriteLine("public key to store for this user and device:");
                Console.WriteLine(result.PublicKeyPem);
                return 0;
            }

            Console.WriteLine("rejectReason  : " + result.RejectReason);
            return 1;
        }

        /// <summary>
        /// iOS mode. Input is a small JSON file holding what the app sent to the
        /// server. Field names are documented in the README.
        /// </summary>
        private static int RunIos(string[] args)
        {
            if (args.Length < 5)
            {
                Console.WriteLine("usage: verify-attestation ios <input.json> <AppleAppAttestRoot.pem> <appId> <bundleId> [--production]");
                Console.WriteLine();
                Console.WriteLine("input.json:");
                Console.WriteLine("  { \"attestationObjectBase64\": \"...\",");
                Console.WriteLine("    \"appAttestKeyIdBase64\":   \"...\",");
                Console.WriteLine("    \"nonceBase64\":            \"...\",");
                Console.WriteLine("    \"publicKeyPem\":           \"-----BEGIN PUBLIC KEY-----...\",");
                Console.WriteLine("    \"deviceId\":               \"...\" }");
                return 2;
            }

            var jsonPath = args[1];
            var rootPath = args[2];
            var appId = args[3];
            var bundleId = args[4];
            var requireProduction = Array.IndexOf(args, "--production") >= 0;

            if (!File.Exists(jsonPath)) { Console.Error.WriteLine("no such file: " + jsonPath); return 2; }
            if (!File.Exists(rootPath)) { Console.Error.WriteLine("no such file: " + rootPath); return 2; }

            using var doc = System.Text.Json.JsonDocument.Parse(File.ReadAllText(jsonPath));
            var r = doc.RootElement;
            string Field(string name) =>
                r.TryGetProperty(name, out var v) ? v.GetString() : "";

            var result = new IosAppAttestVerifier().Verify(
                Field("attestationObjectBase64"),
                Field("appAttestKeyIdBase64"),
                Field("nonceBase64"),
                Field("publicKeyPem"),
                Field("deviceId"),
                File.ReadAllText(rootPath),
                appId, bundleId, requireProduction);

            Console.WriteLine(result.Report);
            Console.WriteLine();

            if (!result.IsValid)
            {
                Console.WriteLine("rejectReason  : " + result.RejectReason);
                return 1;
            }

            Console.WriteLine("environment   : " + result.Environment);
            Console.WriteLine("appId         : " + appId);
            Console.WriteLine();
            Console.WriteLine("public key to store for this user and device:");
            Console.WriteLine(result.PublicKeyPem);
            return 0;
        }

        /// <summary>
        /// Unattested enrollment mode. Used for Huawei, where no usable attestation
        /// exists. Validates the public key from the request body and nothing more.
        /// </summary>
        private static int RunKey(string[] args)
        {
            if (args.Length < 2)
            {
                Console.WriteLine("usage: verify-attestation key <publicKey.pem>");
                return 2;
            }
            if (!File.Exists(args[1])) { Console.Error.WriteLine("no such file: " + args[1]); return 2; }

            new BiometricKeyValidator().ValidateBiometricPublicKey(
                File.ReadAllText(args[1]),
                out bool isValid, out string reason, out string curve,
                out string trustLevel, out string report);

            Console.WriteLine(report);
            Console.WriteLine();
            Console.WriteLine("curve         : " + curve);
            Console.WriteLine("trustLevel    : " + trustLevel);
            if (!isValid) Console.WriteLine("rejectReason  : " + reason);
            return isValid ? 0 : 1;
        }

        /// <summary>Exploration helper. Pulls the challenge out of the leaf without judging it.</summary>
        private static string ReadNonceFromChain(string chainPem)
        {
            var certs = Pem.ReadCertificates(chainPem);
            foreach (var der in certs)
            {
                var cert = new System.Security.Cryptography.X509Certificates.X509Certificate2(der);
                var ext = CertificateChain.FindAttestationExtension(cert);
                if (ext == null) continue;
                try
                {
                    var kd = KeyDescription.Parse(ext);
                    return Convert.ToBase64String(kd.AttestationChallenge);
                }
                catch
                {
                    return null;
                }
            }
            return null;
        }
    }
}
