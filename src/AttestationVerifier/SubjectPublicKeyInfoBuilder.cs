using System.Formats.Asn1;
using System.Security.Cryptography.X509Certificates;

namespace AttestationVerifier
{
    /// <summary>
    /// Rebuilds the SubjectPublicKeyInfo structure from the parts X509Certificate2
    /// exposes on every target framework, including .NET Framework 4.8 where
    /// ExportSubjectPublicKeyInfo does not exist.
    ///
    ///   SubjectPublicKeyInfo ::= SEQUENCE {
    ///       algorithm         AlgorithmIdentifier,
    ///       subjectPublicKey  BIT STRING }
    /// </summary>
    internal static class SubjectPublicKeyInfoBuilder
    {
        public static byte[] Build(X509Certificate2 cert)
        {
            var writer = new AsnWriter(AsnEncodingRules.DER);

            using (writer.PushSequence())
            {
                using (writer.PushSequence())
                {
                    writer.WriteObjectIdentifier(cert.PublicKey.Oid.Value);

                    var parameters = cert.PublicKey.EncodedParameters;
                    if (parameters != null && parameters.RawData != null && parameters.RawData.Length > 0)
                    {
                        writer.WriteEncodedValue(parameters.RawData);
                    }
                    else
                    {
                        writer.WriteNull();
                    }
                }

                writer.WriteBitString(cert.PublicKey.EncodedKeyValue.RawData);
            }

            return writer.Encode();
        }
    }
}
