using System;
using System.Collections.Generic;
using System.Formats.Asn1;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace AttestationVerifier
{
    /// <summary>
    /// Certificate path handling, done by hand instead of with X509Chain.
    ///
    /// Why by hand:
    ///   1. Older devices (Galaxy A50 and its generation) ship a factory root whose
    ///      validity has already lapsed. Standard X.509 path validation rejects them.
    ///      Android's rule is to trust the pinned anchors, not the copy the phone sends.
    ///   2. X509Chain behaves differently on Windows, Linux and macOS, and a server
    ///      may run on any of them.
    ///   3. Every step is visible, which is the point of this module.
    /// </summary>
    public static class CertificateChain
    {
        // ---------------------------------------------------------------------
        // Ordering
        // ---------------------------------------------------------------------

        /// <summary>
        /// Sorts the certificates leaf first. The leaf is the certificate that is not
        /// the issuer of any other certificate in the set. Chain length is not assumed:
        /// real chains are 3, 4 or 5 certificates long depending on the device.
        /// </summary>
        public static List<X509Certificate2> Order(IEnumerable<X509Certificate2> certs)
        {
            var all = certs.ToList();
            if (all.Count == 0) return all;

            var leaf = all.FirstOrDefault(c =>
                !all.Any(other => !ReferenceEquals(other, c) && IsIssuedBy(other, c)));

            if (leaf == null) leaf = all[0];

            var ordered = new List<X509Certificate2> { leaf };
            var remaining = all.Where(c => !ReferenceEquals(c, leaf)).ToList();

            var current = leaf;
            while (true)
            {
                var next = remaining.FirstOrDefault(c => IsIssuedBy(current, c));
                if (next == null) break;
                ordered.Add(next);
                remaining.Remove(next);
                current = next;
                if (IsSelfSigned(current)) break;
            }

            // anything left over is unreachable from the leaf; keep it at the end
            ordered.AddRange(remaining);
            return ordered;
        }

        /// <summary>True when child.Issuer equals candidateIssuer.Subject (byte compare, not string).</summary>
        public static bool IsIssuedBy(X509Certificate2 child, X509Certificate2 candidateIssuer)
        {
            return child.IssuerName.RawData.SequenceEqual(candidateIssuer.SubjectName.RawData);
        }

        public static bool IsSelfSigned(X509Certificate2 cert)
        {
            return cert.IssuerName.RawData.SequenceEqual(cert.SubjectName.RawData);
        }

        // ---------------------------------------------------------------------
        // Signature verification
        // ---------------------------------------------------------------------

        /// <summary>
        /// Verifies that <paramref name="child"/> was signed by the private key
        /// belonging to <paramref name="issuer"/>.
        ///
        /// A certificate is three parts: tbsCertificate (the body), the signature
        /// algorithm, and the signature. The signature covers the exact DER bytes of
        /// the body. Change one byte of the package name and this check fails.
        ///
        ///   Certificate ::= SEQUENCE {
        ///       tbsCertificate       TBSCertificate,
        ///       signatureAlgorithm   AlgorithmIdentifier,
        ///       signatureValue       BIT STRING }
        /// </summary>
        public static bool VerifySignature(X509Certificate2 child, X509Certificate2 issuer)
        {
            try
            {
                byte[] tbs;
                string sigOid;
                byte[] signature;
                Split(child.RawData, out tbs, out sigOid, out signature);

                HashAlgorithmName hash;
                bool isEcdsa;
                if (!MapAlgorithm(sigOid, out hash, out isEcdsa)) return false;

                if (isEcdsa)
                {
                    using (var ecdsa = issuer.GetECDsaPublicKey())
                    {
                        if (ecdsa == null) return false;
                        int fieldSize = (ecdsa.KeySize + 7) / 8;
                        var raw = DerToRawEcdsaSignature(signature, fieldSize);
                        if (raw == null) return false;
                        return ecdsa.VerifyData(tbs, raw, hash);
                    }
                }

                using (var rsa = issuer.GetRSAPublicKey())
                {
                    if (rsa == null) return false;
                    return rsa.VerifyData(tbs, signature, hash, RSASignaturePadding.Pkcs1);
                }
            }
            catch
            {
                return false;
            }
        }

        private static void Split(byte[] rawCert, out byte[] tbs, out string sigOid, out byte[] signature)
        {
            var reader = new AsnReader(rawCert, AsnEncodingRules.DER);
            var cert = reader.ReadSequence();

            // tbsCertificate: keep the encoded value, tag and length included,
            // because that is exactly what was hashed when signing.
            tbs = cert.ReadEncodedValue().ToArray();

            var algId = cert.ReadSequence();
            sigOid = algId.ReadObjectIdentifier();

            int unusedBits;
            signature = cert.ReadBitString(out unusedBits);
        }

        private static bool MapAlgorithm(string oid, out HashAlgorithmName hash, out bool isEcdsa)
        {
            switch (oid)
            {
                case "1.2.840.113549.1.1.5":  hash = HashAlgorithmName.SHA1;   isEcdsa = false; return true;
                case "1.2.840.113549.1.1.11": hash = HashAlgorithmName.SHA256; isEcdsa = false; return true;
                case "1.2.840.113549.1.1.12": hash = HashAlgorithmName.SHA384; isEcdsa = false; return true;
                case "1.2.840.113549.1.1.13": hash = HashAlgorithmName.SHA512; isEcdsa = false; return true;
                case "1.2.840.10045.4.3.2":   hash = HashAlgorithmName.SHA256; isEcdsa = true;  return true;
                case "1.2.840.10045.4.3.3":   hash = HashAlgorithmName.SHA384; isEcdsa = true;  return true;
                case "1.2.840.10045.4.3.4":   hash = HashAlgorithmName.SHA512; isEcdsa = true;  return true;
                default:                      hash = default(HashAlgorithmName); isEcdsa = false; return false;
            }
        }

        /// <summary>
        /// X.509 stores an ECDSA signature as DER SEQUENCE { INTEGER r, INTEGER s }.
        /// .NET expects the raw IEEE P1363 form: r and s concatenated, each left padded
        /// to the field size. Converting by hand keeps this working on .NET Framework,
        /// where the DER overload of VerifyData does not exist.
        /// </summary>
        private static byte[] DerToRawEcdsaSignature(byte[] der, int fieldSize)
        {
            try
            {
                var reader = new AsnReader(der, AsnEncodingRules.DER);
                var seq = reader.ReadSequence();
                var r = seq.ReadIntegerBytes().ToArray();
                var s = seq.ReadIntegerBytes().ToArray();

                var raw = new byte[fieldSize * 2];
                if (!CopyRightAligned(r, raw, 0, fieldSize)) return null;
                if (!CopyRightAligned(s, raw, fieldSize, fieldSize)) return null;
                return raw;
            }
            catch
            {
                return null;
            }
        }

        private static bool CopyRightAligned(byte[] value, byte[] target, int offset, int size)
        {
            int start = 0;
            while (start < value.Length - 1 && value[start] == 0) start++; // drop DER sign padding
            int length = value.Length - start;
            if (length > size) return false;
            Array.Copy(value, start, target, offset + size - length, length);
            return true;
        }

        // ---------------------------------------------------------------------
        // Extension lookup
        // ---------------------------------------------------------------------

        public const string AttestationExtensionOid = "1.3.6.1.4.1.11129.2.1.17";

        public static byte[] FindAttestationExtension(X509Certificate2 cert)
        {
            foreach (var ext in cert.Extensions)
            {
                if (ext.Oid != null && ext.Oid.Value == AttestationExtensionOid)
                {
                    return ext.RawData;
                }
            }
            return null;
        }
    }
}
