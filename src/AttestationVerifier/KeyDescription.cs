using System;
using System.Collections.Generic;
using System.Formats.Asn1;
using System.Numerics;

namespace AttestationVerifier
{
    /// <summary>
    /// The contents of extension 1.3.6.1.4.1.11129.2.1.17 in the leaf certificate.
    /// This is what the secure hardware wrote about the key it just created.
    ///
    ///   KeyDescription ::= SEQUENCE {
    ///       attestationVersion         INTEGER,
    ///       attestationSecurityLevel   ENUMERATED,   -- 0 Software, 1 TEE, 2 StrongBox
    ///       keymasterVersion           INTEGER,
    ///       keymasterSecurityLevel     ENUMERATED,
    ///       attestationChallenge       OCTET STRING, -- the server nonce
    ///       uniqueId                   OCTET STRING,
    ///       softwareEnforced           AuthorizationList,
    ///       teeEnforced                AuthorizationList }
    /// </summary>
    public sealed class KeyDescription
    {
        public int AttestationVersion;
        public int AttestationSecurityLevel;
        public int KeymasterVersion;
        public int KeymasterSecurityLevel;
        public byte[] AttestationChallenge;
        public byte[] UniqueId;
        public AuthorizationList SoftwareEnforced;
        public AuthorizationList TeeEnforced;

        public static string SecurityLevelName(int level)
        {
            switch (level)
            {
                case 0: return "Software";
                case 1: return "TrustedEnvironment";
                case 2: return "StrongBox";
                default: return "Unknown(" + level + ")";
            }
        }

        public static KeyDescription Parse(byte[] extensionOctets)
        {
            // Callers hand us the extension in one of two shapes:
            //   X509Extension.RawData      already unwrapped, starts with the SEQUENCE
            //   the raw DER of extnValue   an OCTET STRING wrapping the SEQUENCE
            // Accept both instead of forcing the caller to know which one it has.
            var reader = new AsnReader(extensionOctets, AsnEncodingRules.DER);
            if (reader.PeekTag() == Asn1Tag.PrimitiveOctetString)
            {
                reader = new AsnReader(reader.ReadOctetString(), AsnEncodingRules.DER);
            }
            var seq = reader.ReadSequence();

            var kd = new KeyDescription();
            kd.AttestationVersion = (int)seq.ReadInteger();
            kd.AttestationSecurityLevel = ReadEnumerated(seq);
            kd.KeymasterVersion = (int)seq.ReadInteger();
            kd.KeymasterSecurityLevel = ReadEnumerated(seq);
            kd.AttestationChallenge = seq.ReadOctetString();
            kd.UniqueId = seq.ReadOctetString();
            kd.SoftwareEnforced = AuthorizationList.Parse(seq);
            kd.TeeEnforced = AuthorizationList.Parse(seq);
            return kd;
        }

        internal static int ReadEnumerated(AsnReader reader)
        {
            var bytes = reader.ReadEnumeratedBytes().ToArray();
            int value = 0;
            foreach (var b in bytes) value = (value << 8) | b;
            return value;
        }
    }

    /// <summary>
    /// One of the two authorization lists. Every entry is an EXPLICIT context tagged
    /// value inside a SEQUENCE, and every entry is optional, so the parser reads tags
    /// it recognises and skips the rest. Unknown tags appear on newer KeyMint versions
    /// and must not break parsing.
    ///
    /// Which list matters:
    ///   teeEnforced      written by the secure hardware. This is the evidence.
    ///   softwareEnforced written by the OS. Key properties found here prove nothing.
    ///                    The one useful field here is attestationApplicationId, which
    ///                    the keystore daemon fills in, not the calling app.
    /// </summary>
    public sealed class AuthorizationList
    {
        // tag numbers from the Android attestation schema
        private const int TagPurpose = 1;
        private const int TagAlgorithm = 2;
        private const int TagKeySize = 3;
        private const int TagDigest = 5;
        private const int TagPadding = 6;
        private const int TagEcCurve = 10;
        private const int TagNoAuthRequired = 503;
        private const int TagUserAuthType = 504;
        private const int TagAuthTimeout = 505;
        private const int TagCreationDateTime = 701;
        private const int TagOrigin = 702;
        private const int TagRootOfTrust = 704;
        private const int TagOsVersion = 705;
        private const int TagOsPatchLevel = 706;
        private const int TagAttestationApplicationId = 709;

        public List<int> Purpose = new List<int>();
        public int? Algorithm;
        public int? KeySize;
        public List<int> Digest = new List<int>();
        public int? EcCurve;
        public bool NoAuthRequired;          // presence of the tag, not a value
        public int? UserAuthType;
        public int? AuthTimeout;
        public int? Origin;
        public RootOfTrust RootOfTrust;
        public int? OsVersion;
        public int? OsPatchLevel;
        public string PackageName;
        public int? PackageVersion;
        public List<byte[]> SigningDigests = new List<byte[]>();

        // purpose values
        public const int PurposeSign = 2;
        // algorithm values
        public const int AlgorithmEc = 3;
        // ecCurve values
        public const int CurveP256 = 1;
        // digest values
        public const int DigestSha256 = 4;
        // userAuthType is a bit mask
        public const int AuthTypePassword = 1;
        public const int AuthTypeFingerprint = 2;   // this is what BIOMETRIC_STRONG maps to
        // origin values
        public const int OriginGenerated = 0;

        public static AuthorizationList Parse(AsnReader parent)
        {
            var list = new AuthorizationList();
            var seq = parent.ReadSequence();

            while (seq.HasData)
            {
                var tag = seq.PeekTag();
                if (tag.TagClass != TagClass.ContextSpecific)
                {
                    seq.ReadEncodedValue();
                    continue;
                }

                // EXPLICIT tagging: the context tag is a wrapper around the real value
                AsnReader item;
                try
                {
                    item = seq.ReadSequence(tag);
                }
                catch
                {
                    seq.ReadEncodedValue();
                    continue;
                }

                try
                {
                    switch (tag.TagValue)
                    {
                        case TagPurpose:
                            list.Purpose = ReadIntSet(item);
                            break;
                        case TagAlgorithm:
                            list.Algorithm = (int)item.ReadInteger();
                            break;
                        case TagKeySize:
                            list.KeySize = (int)item.ReadInteger();
                            break;
                        case TagDigest:
                            list.Digest = ReadIntSet(item);
                            break;
                        case TagEcCurve:
                            list.EcCurve = (int)item.ReadInteger();
                            break;
                        case TagNoAuthRequired:
                            list.NoAuthRequired = true;   // tag present means auth is NOT required
                            break;
                        case TagUserAuthType:
                            list.UserAuthType = (int)item.ReadInteger();
                            break;
                        case TagAuthTimeout:
                            list.AuthTimeout = (int)item.ReadInteger();
                            break;
                        case TagOrigin:
                            list.Origin = (int)item.ReadInteger();
                            break;
                        case TagOsVersion:
                            list.OsVersion = (int)item.ReadInteger();
                            break;
                        case TagOsPatchLevel:
                            list.OsPatchLevel = (int)item.ReadInteger();
                            break;
                        case TagRootOfTrust:
                            list.RootOfTrust = RootOfTrust.Parse(item);
                            break;
                        case TagAttestationApplicationId:
                            list.ReadApplicationId(item.ReadOctetString());
                            break;
                        case TagPadding:
                        case TagCreationDateTime:
                        default:
                            break; // recognised but unused, or unknown on newer KeyMint
                    }
                }
                catch
                {
                    // a field we cannot decode must not abort the whole parse
                }
            }

            return list;
        }

        private static List<int> ReadIntSet(AsnReader item)
        {
            var values = new List<int>();
            var set = item.ReadSetOf();
            while (set.HasData) values.Add((int)set.ReadInteger());
            return values;
        }

        /// <summary>
        ///   AttestationApplicationId ::= SEQUENCE {
        ///       packageInfos      SET OF AttestationPackageInfo,
        ///       signatureDigests  SET OF OCTET STRING }
        ///   AttestationPackageInfo ::= SEQUENCE {
        ///       packageName  OCTET STRING,
        ///       version      INTEGER }
        /// </summary>
        private void ReadApplicationId(byte[] der)
        {
            var reader = new AsnReader(der, AsnEncodingRules.DER);
            var seq = reader.ReadSequence();

            var packages = seq.ReadSetOf();
            if (packages.HasData)
            {
                var info = packages.ReadSequence();
                PackageName = System.Text.Encoding.UTF8.GetString(info.ReadOctetString());
                PackageVersion = (int)info.ReadInteger();
            }

            var digests = seq.ReadSetOf();
            while (digests.HasData) SigningDigests.Add(digests.ReadOctetString());
        }
    }

    /// <summary>
    ///   RootOfTrust ::= SEQUENCE {
    ///       verifiedBootKey    OCTET STRING,
    ///       deviceLocked       BOOLEAN,
    ///       verifiedBootState  ENUMERATED,   -- 0 Verified, 1 SelfSigned, 2 Unverified, 3 Failed
    ///       verifiedBootHash   OCTET STRING  -- absent on attestation version 1 and 2
    ///   }
    /// </summary>
    public sealed class RootOfTrust
    {
        public byte[] VerifiedBootKey;
        public bool DeviceLocked;
        public int VerifiedBootState;
        public byte[] VerifiedBootHash;

        public const int StateVerified = 0;

        public static string StateName(int state)
        {
            switch (state)
            {
                case 0: return "Verified";
                case 1: return "SelfSigned";
                case 2: return "Unverified";
                case 3: return "Failed";
                default: return "Unknown(" + state + ")";
            }
        }

        public static RootOfTrust Parse(AsnReader item)
        {
            var seq = item.ReadSequence();
            var rot = new RootOfTrust();
            rot.VerifiedBootKey = seq.ReadOctetString();
            rot.DeviceLocked = seq.ReadBoolean();
            rot.VerifiedBootState = KeyDescription.ReadEnumerated(seq);
            if (seq.HasData) rot.VerifiedBootHash = seq.ReadOctetString();
            return rot;
        }
    }
}
