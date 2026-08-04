using System;
using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Text.RegularExpressions;

namespace AttestationVerifier
{
    /// <summary>
    /// Loads an EC public key from a SubjectPublicKeyInfo PEM, the format this
    /// module stores after enrollment.
    ///
    /// Written by hand rather than with ImportSubjectPublicKeyInfo, which does not
    /// exist on .NET Framework 4.8, which many enterprise servers still run.
    ///
    ///   SubjectPublicKeyInfo ::= SEQUENCE {
    ///       algorithm  SEQUENCE { OID ecPublicKey, OID namedCurve },
    ///       subjectPublicKey  BIT STRING }   -- 0x04 || X || Y, uncompressed point
    /// </summary>
    public static class PublicKeyReader
    {
        private const string OidEcPublicKey = "1.2.840.10045.2.1";

        private static readonly Regex Block = new Regex(
            "-----BEGIN PUBLIC KEY-----(?<body>.*?)-----END PUBLIC KEY-----",
            RegexOptions.Singleline | RegexOptions.Compiled);

        public static ECDsa ReadEcPublicKey(string pem)
        {
            var der = ExtractDer(pem);

            var reader = new AsnReader(der, AsnEncodingRules.DER);
            var spki = reader.ReadSequence();

            var algorithm = spki.ReadSequence();
            var keyType = algorithm.ReadObjectIdentifier();
            if (keyType != OidEcPublicKey)
            {
                throw new CryptographicException("not an EC public key, algorithm OID is " + keyType);
            }
            var curveOid = algorithm.ReadObjectIdentifier();

            int unusedBits;
            var point = spki.ReadBitString(out unusedBits);

            if (point.Length < 1 || point[0] != 0x04)
            {
                throw new CryptographicException("expected an uncompressed EC point");
            }

            int fieldSize = (point.Length - 1) / 2;
            var x = new byte[fieldSize];
            var y = new byte[fieldSize];
            Array.Copy(point, 1, x, 0, fieldSize);
            Array.Copy(point, 1 + fieldSize, y, 0, fieldSize);

            var parameters = new ECParameters
            {
                Curve = ECCurve.CreateFromValue(curveOid),
                Q = new ECPoint { X = x, Y = y }
            };
            parameters.Validate();

            return ECDsa.Create(parameters);
        }

        private static byte[] ExtractDer(string pem)
        {
            if (string.IsNullOrWhiteSpace(pem)) throw new ArgumentException("empty public key");

            var text = pem.Replace("\\n", "\n").Replace("\\r", "");
            var match = Block.Match(text);
            var body = match.Success ? match.Groups["body"].Value : text;

            var cleaned = Regex.Replace(body, "[^A-Za-z0-9+/=]", "");
            return Convert.FromBase64String(cleaned);
        }
    }
}
