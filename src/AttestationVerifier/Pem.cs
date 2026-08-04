using System;
using System.Collections.Generic;
using System.Text;
using System.Text.RegularExpressions;

namespace AttestationVerifier
{
    /// <summary>
    /// Tolerant PEM reader.
    ///
    /// The mobile app may deliver the chain in several shapes, all of which appear
    /// in real logs:
    ///   - a JSON array of PEM strings
    ///   - one string with literal "\n" escapes instead of real newlines
    ///   - PEM blocks separated by ", "
    ///   - plain concatenated PEM
    /// Rather than guessing the shape, we pull out every BEGIN/END CERTIFICATE block
    /// and ignore whatever sits between them.
    /// </summary>
    public static class Pem
    {
        private static readonly Regex Block = new Regex(
            "-----BEGIN CERTIFICATE-----(?<body>.*?)-----END CERTIFICATE-----",
            RegexOptions.Singleline | RegexOptions.Compiled);

        public static List<byte[]> ReadCertificates(string text)
        {
            var result = new List<byte[]>();
            if (string.IsNullOrWhiteSpace(text)) return result;

            // Turn escape sequences into real characters first. This matters:
            // a literal backslash-n leaves an "n" behind, and "n" is a valid base64
            // character, so filtering without unescaping silently corrupts the data.
            text = text
                .Replace("\\r\\n", "\n")
                .Replace("\\n", "\n")
                .Replace("\\r", "\n")
                .Replace("\\t", " ")
                .Replace("\\/", "/");

            foreach (Match m in Block.Matches(text))
            {
                var body = m.Groups["body"].Value;
                var b64 = new StringBuilder(body.Length);
                foreach (var c in body)
                {
                    // keep base64 alphabet only, drop \n, \\n, spaces, quotes, commas
                    if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                        (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '=')
                    {
                        b64.Append(c);
                    }
                }
                if (b64.Length == 0) continue;
                result.Add(Convert.FromBase64String(b64.ToString()));
            }

            return result;
        }

        public static string WritePublicKey(byte[] subjectPublicKeyInfo)
        {
            var b64 = Convert.ToBase64String(subjectPublicKeyInfo);
            var sb = new StringBuilder();
            sb.Append("-----BEGIN PUBLIC KEY-----\n");
            for (int i = 0; i < b64.Length; i += 64)
            {
                sb.Append(b64, i, Math.Min(64, b64.Length - i)).Append('\n');
            }
            sb.Append("-----END PUBLIC KEY-----");
            return sb.ToString();
        }

        /// <summary>Accepts both standard and URL-safe base64, with or without padding.</summary>
        public static byte[] DecodeBase64(string value)
        {
            if (string.IsNullOrWhiteSpace(value)) return new byte[0];
            var s = value.Trim().Replace('-', '+').Replace('_', '/');
            switch (s.Length % 4)
            {
                case 2: s += "=="; break;
                case 3: s += "="; break;
            }
            return Convert.FromBase64String(s);
        }

        public static string ToHex(byte[] bytes)
        {
            if (bytes == null) return "";
            var sb = new StringBuilder(bytes.Length * 2);
            foreach (var b in bytes) sb.Append(b.ToString("x2"));
            return sb.ToString();
        }
    }
}
