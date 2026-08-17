using NUnit.Framework;

using NTSConformance.Core;
using NTSConformance.Core.RawNtsKe;

using org.GraphDefined.Vanaheimr.Norn.NTS;
using org.GraphDefined.Vanaheimr.Norn.NTS.NTSKERecords;

namespace NTSConformance.NTSKE.Tests;

/// <summary>
/// RFC 8915 §4.1 NTS-KE record framing.
///
/// The record header is deliberately unlike an NTP extension field: the top bit of the
/// first word is the Critical Bit leaving 15 bits of type, the length counts only the body,
/// and there is no padding. Getting any of that wrong shifts every subsequent record.
///
/// Encoded and decoded both by Norn and by <see cref="RawNtsKeCodec"/>, which was written
/// from the RFC independently.
/// </summary>
[TestFixture]
public class NtsKeRecordFramingTests
{

    #region Header layout

    /// <summary>
    /// The critical bit is the most significant bit of the first word, and the record type
    /// occupies the remaining 15. Norn's encoding must be byte-identical to the reference.
    /// </summary>
    [TestCase((UInt16) 0, true,  TestName = "CriticalBit_EndOfMessage_Critical")]
    [TestCase((UInt16) 1, true,  TestName = "CriticalBit_NextProtocol_Critical")]
    [TestCase((UInt16) 4, false, TestName = "CriticalBit_AeadNegotiation_NonCritical")]
    [TestCase((UInt16) 5, false, TestName = "CriticalBit_NewCookie_NonCritical")]
    public void RecordHeader_MatchesReference(UInt16 recordType, Boolean isCritical)
    {

        var body      = new Byte[] { 0xAA, 0xBB };

        var reference = new RawNtsKeRecord(isCritical, recordType, body).ToByteArray();
        var norn      = new NTSKE_Record(isCritical, (NTSKE_RecordTypes) recordType, body).ToByteArray();

        Assert.That(norn, Is.EqualTo(reference).AsCollection, Bytes.Diff(reference, norn));

    }


    /// <summary>
    /// The critical bit must not bleed into the type. A record of type 5 with the bit set
    /// encodes as 0x8005, and must decode back to type 5 — not 0x8005.
    /// </summary>
    [Test]
    public void CriticalBit_IsSeparatedFromTheType()
    {

        var encoded = new RawNtsKeRecord(true, RawNtsKeRecordTypes.NewCookieForNtpv4, [ 0x01, 0x02, 0x03, 0x04 ]).ToByteArray();

        Assert.That(encoded[0], Is.EqualTo(0x80), "the critical bit is the top bit of the first octet");
        Assert.That(encoded[1], Is.EqualTo(0x05), "the low octet carries the type");

        if (!NTSKE_Record.TryParse(encoded, out var parsedRecords, out var errorResponse))
        {
            Assert.Fail($"Norn should parse a critical New Cookie record: {errorResponse}");
            return;
        }

        var parsed = parsedRecords.First();

        Assert.Multiple(() => {
            Assert.That(parsed.IsCritical,     Is.True,                                              "the critical bit");
            Assert.That((UInt16) parsed.Type,  Is.EqualTo(RawNtsKeRecordTypes.NewCookieForNtpv4),     "the type, with the bit masked off");
            Assert.That(parsed.Body,           Is.EqualTo(new Byte[] { 1, 2, 3, 4 }).AsCollection);
        });

    }


    /// <summary>
    /// The length field counts the body only. A 4-octet body means a declared length of 4
    /// and a total record of 8 octets — confusing this with the NTP extension field
    /// convention (where the length includes the header) shifts everything after it.
    /// </summary>
    [Test]
    public void BodyLength_ExcludesTheHeader()
    {

        var encoded = new RawNtsKeRecord(false, RawNtsKeRecordTypes.NewCookieForNtpv4,
                                         [ 0x01, 0x02, 0x03, 0x04 ]).ToByteArray();

        Assert.Multiple(() => {
            Assert.That(encoded.Length, Is.EqualTo(8), "4 octets of header plus a 4-octet body");
            Assert.That(encoded[2],     Is.EqualTo(0x00));
            Assert.That(encoded[3],     Is.EqualTo(0x04), "the declared length is the body length");
        });

    }


    /// <summary>
    /// An empty body is legal, and End of Message always has one.
    /// </summary>
    [Test]
    public void EndOfMessage_IsCriticalWithAnEmptyBody()
    {

        var reference = RawNtsKeRecord.EndOfMessage().ToByteArray();
        var norn      = NTSKE_Record.EndOfMessage.ToByteArray();

        Assert.Multiple(() => {
            Assert.That(reference, Is.EqualTo(new Byte[] { 0x80, 0x00, 0x00, 0x00 }).AsCollection,
                        "End of Message is the critical bit, type 0 and a zero length");
            Assert.That(norn, Is.EqualTo(reference).AsCollection, Bytes.Diff(reference, norn));
        });

    }

    #endregion

    #region Negotiation record bodies

    /// <summary>
    /// RFC 8915 §4.1.2: the Next Protocol Negotiation body is a sequence of 16-bit
    /// protocol ids, big-endian. NTPv4 is 0.
    /// </summary>
    [Test]
    public void NextProtocolNegotiation_CarriesNtpv4()
    {

        var reference = RawNtsKeRecord.NextProtocolNegotiation(RawNtsKeNextProtocols.Ntpv4).ToByteArray();
        var norn      = NTSKE_Record.NTSNextProtocolNegotiation.ToByteArray();

        Assert.That(norn, Is.EqualTo(reference).AsCollection, Bytes.Diff(reference, norn));

    }


    /// <summary>
    /// RFC 8915 §4.1.5: the AEAD Algorithm Negotiation body is a sequence of 16-bit IANA
    /// AEAD ids. AES-SIV-CMAC-256 is 15.
    ///
    /// The critical bit is compared loosely on purpose — §4.1.5 says it MAY be set, so
    /// either choice is conformant. Norn sets it; the reference does not. What must match is
    /// the record type and the body.
    /// </summary>
    [Test]
    public void AeadAlgorithmNegotiation_CarriesAesSivCmac256()
    {

        var norn = NTSKE_Record.AEADAlgorithmNegotiation(AEADAlgorithms.AES_SIV_CMAC_256).ToByteArray();

        if (!RawNtsKeCodec.TryDecode(norn, out var decoded, out var errorResponse))
        {
            Assert.Fail($"the reference decoder should read Norn's AEAD record: {errorResponse}");
            return;
        }

        var record = decoded!.Single();

        Assert.Multiple(() => {

            Assert.That(record.RecordType,
                        Is.EqualTo(RawNtsKeRecordTypes.AeadAlgorithmNegotiation),
                        "record type 4");

            Assert.That(RawNtsKeCodec.ReadUInt16Body(record),
                        Is.EqualTo(new UInt16[] { 15 }).AsCollection,
                        "AES-SIV-CMAC-256 is IANA AEAD id 15, big-endian");

        });

    }


    /// <summary>
    /// The IANA AEAD registry ids Norn enumerates must match their assigned numbers.
    /// </summary>
    [TestCase(AEADAlgorithms.AES_SIV_CMAC_256,   (UInt16) 15)]
    [TestCase(AEADAlgorithms.AES_SIV_CMAC_384,   (UInt16) 16)]
    [TestCase(AEADAlgorithms.AES_SIV_CMAC_512,   (UInt16) 17)]
    [TestCase(AEADAlgorithms.AES_128_GCM_SIV,    (UInt16) 30)]
    [TestCase(AEADAlgorithms.AES_256_GCM_SIV,    (UInt16) 31)]
    public void AeadAlgorithmIds_MatchTheIanaRegistry(AEADAlgorithms algorithm, UInt16 expectedId)
    {

        Assert.Multiple(() => {

            Assert.That((UInt16) algorithm, Is.EqualTo(expectedId));

            Assert.That(algorithm.GetBytes(),
                        Is.EqualTo(new Byte[] { (Byte) (expectedId >> 8), (Byte) expectedId }).AsCollection,
                        "ids go on the wire big-endian");

        });

    }

    #endregion

    #region Record stream decoding

    /// <summary>
    /// A conformant server response must decode to the same records in both
    /// implementations: next protocol, AEAD, cookies, End of Message.
    /// </summary>
    [Test]
    public void ServerResponse_DecodesIdenticallyInBothImplementations()
    {

        var encoded = RawNtsKeCodec.Encode([
                          RawNtsKeRecord.NextProtocolNegotiation(RawNtsKeNextProtocols.Ntpv4),
                          RawNtsKeRecord.AeadAlgorithmNegotiation(15),
                          RawNtsKeRecord.NewCookieForNtpv4(Enumerable.Repeat((Byte) 0xC0, 104).ToArray()),
                          RawNtsKeRecord.NewCookieForNtpv4(Enumerable.Repeat((Byte) 0xC1, 104).ToArray()),
                          RawNtsKeRecord.EndOfMessage()
                      ]);

        var referenceOk = RawNtsKeCodec.TryDecode(encoded, out var referenceRecords, out var referenceError);
        var nornOk      = NTSKE_Record.TryParse(encoded, out var nornRecords, out var nornError);

        Assert.Multiple(() => {

            Assert.That(referenceOk, Is.True, $"the reference decoder: {referenceError}");
            Assert.That(nornOk,      Is.True, $"Norn: {nornError}");

            Assert.That(nornRecords?.Count(), Is.EqualTo(referenceRecords?.Count),
                        "both decoders should find the same number of records");

            Assert.That(nornRecords?.Count(record => record.Type == NTSKE_RecordTypes.NewCookieForNTPv4),
                        Is.EqualTo(2),
                        "both cookies should be recovered");

        });

    }


    /// <summary>
    /// A record whose declared body length runs past the end of the message must be
    /// rejected, not silently truncated.
    /// </summary>
    [Test]
    public void RecordBodyOverrunningTheMessage_IsRejected()
    {

        var encoded = RawNtsKeCodec.Encode([
                          RawNtsKeRecord.NextProtocolNegotiation(RawNtsKeNextProtocols.Ntpv4) with { LengthOverride = 500 }
                      ]);

        Assert.Multiple(() => {

            Assert.That(RawNtsKeCodec.TryDecode(encoded, out _, out _), Is.False,
                        "the reference decoder should reject the overrun");

            Assert.That(NTSKE_Record.TryParse(encoded, out _, out _), Is.False,
                        "Norn should reject a record body that runs past the end of the message");

        });

    }


    /// <summary>
    /// RFC 8915 §4: a message ends at End of Message. Anything after it is not part of the
    /// message and must not be decoded as further records.
    /// </summary>
    [Test]
    public void RecordsAfterEndOfMessage_AreNotDecoded()
    {

        var encoded = RawNtsKeCodec.Encode([
                          RawNtsKeRecord.NextProtocolNegotiation(RawNtsKeNextProtocols.Ntpv4),
                          RawNtsKeRecord.EndOfMessage(),
                          RawNtsKeRecord.NewCookieForNtpv4(Enumerable.Repeat((Byte) 0xEE, 104).ToArray())
                      ]);

        if (!RawNtsKeCodec.TryDecode(encoded, out var records, out var errorResponse))
        {
            Assert.Fail($"the message up to End of Message is well formed: {errorResponse}");
            return;
        }

        Assert.That(records!.Any(record => record.RecordType == RawNtsKeRecordTypes.NewCookieForNtpv4),
                    Is.False,
                    "a cookie placed after End of Message must not be treated as part of the message");

    }

    #endregion

    #region Error and warning records

    /// <summary>
    /// RFC 8915 §4.1.3 error codes are 16-bit values with the critical bit set:
    /// 0 unrecognized critical record, 1 bad request, 2 internal server error.
    /// </summary>
    [TestCase(RawNtsKeErrorCodes.UnrecognizedCriticalRecord)]
    [TestCase(RawNtsKeErrorCodes.BadRequest)]
    [TestCase(RawNtsKeErrorCodes.InternalServerError)]
    public void ErrorRecord_IsCriticalAndCarriesA16BitCode(UInt16 errorCode)
    {

        var encoded = RawNtsKeRecord.Error(errorCode).ToByteArray();

        Assert.Multiple(() => {
            Assert.That(encoded[0] & 0x80, Is.EqualTo(0x80), "an Error record has the critical bit set");
            Assert.That(encoded[1],        Is.EqualTo(RawNtsKeRecordTypes.Error));
            Assert.That(encoded[3],        Is.EqualTo(2), "the body is a 16-bit code");
            Assert.That(encoded[5],        Is.EqualTo((Byte) errorCode));
        });

    }


    /// <summary>
    /// A client receiving an Error record must fail rather than proceed. Norn's validator
    /// classifies this as a server error, which is the behaviour a caller can act on.
    /// </summary>
    [Test]
    public void ClientRejectsAnErrorRecord()
    {

        var encoded = RawNtsKeCodec.Encode([
                          RawNtsKeRecord.Error(RawNtsKeErrorCodes.BadRequest),
                          RawNtsKeRecord.EndOfMessage()
                      ]);

        if (!NTSKE_Record.TryParse(encoded, out var records, out var parseError))
        {
            Assert.Fail($"the records themselves are well formed: {parseError}");
            return;
        }

        var valid = NTSKERecordValidator.ValidateServerResponse(records!, out var errorMessage, out var errorCategory);

        Assert.Multiple(() => {
            Assert.That(valid,          Is.False, "an Error record must fail validation");
            Assert.That(errorCategory,  Is.EqualTo(NTSKEErrorCategory.ServerError));
            Assert.That(errorMessage,   Is.Not.Null.And.Not.Empty);
        });

    }


    /// <summary>
    /// RFC 8915 §4.1: an unrecognized record with the critical bit set must be rejected;
    /// the same record without the bit must be ignored. This is the whole point of the bit,
    /// and it is what lets the protocol be extended without breaking old peers.
    /// </summary>
    [Test]
    public void UnknownRecord_RejectedOnlyWhenCritical()
    {

        var withoutBit = RawNtsKeCodec.Encode([
                             RawNtsKeRecord.NextProtocolNegotiation(RawNtsKeNextProtocols.Ntpv4),
                             RawNtsKeRecord.AeadAlgorithmNegotiation(15),
                             new RawNtsKeRecord(false, 0x3FFF, [ 0xDE, 0xAD ]),
                             RawNtsKeRecord.NewCookieForNtpv4(Enumerable.Repeat((Byte) 0xC0, 104).ToArray()),
                             RawNtsKeRecord.EndOfMessage()
                         ]);

        var withBit    = RawNtsKeCodec.Encode([
                             RawNtsKeRecord.NextProtocolNegotiation(RawNtsKeNextProtocols.Ntpv4),
                             RawNtsKeRecord.AeadAlgorithmNegotiation(15),
                             new RawNtsKeRecord(true, 0x3FFF, [ 0xDE, 0xAD ]),
                             RawNtsKeRecord.NewCookieForNtpv4(Enumerable.Repeat((Byte) 0xC0, 104).ToArray()),
                             RawNtsKeRecord.EndOfMessage()
                         ]);

        Assert.That(NTSKE_Record.TryParse(withoutBit, out var lenientRecords, out _), Is.True);
        Assert.That(NTSKE_Record.TryParse(withBit,    out var strictRecords,  out _), Is.True);

        var lenientValid = NTSKERecordValidator.ValidateServerResponse(lenientRecords!, out _, out _);
        var strictValid  = NTSKERecordValidator.ValidateServerResponse(strictRecords!,  out _, out var strictCategory);

        Assert.Multiple(() => {

            Assert.That(lenientValid, Is.True,
                        "an unknown record without the critical bit must be ignored, not fatal");

            Assert.That(strictValid, Is.False,
                        "an unknown record with the critical bit set must be rejected");

            Assert.That(strictCategory, Is.EqualTo(NTSKEErrorCategory.UnknownCriticalRecord));

        });

    }

    #endregion

    #region TLS exporter (RFC 8915 §5.1)

    /// <summary>
    /// RFC 8915 §5.1 fixes the exporter label and context exactly:
    /// label "EXPORTER-network-time-security", and a five-octet context of
    /// protocol id (2), AEAD id (2), and a direction octet — 0x00 for client-to-server,
    /// 0x01 for server-to-client.
    ///
    /// These bytes are the entire agreement between two implementations about what the
    /// session keys are; a single wrong octet yields keys that look fine and authenticate
    /// nothing. Asserted here as the literal expected values so a change is deliberate.
    /// </summary>
    [Test]
    public void ExporterContext_IsExactlyAsSpecified()
    {

        var aeadBytes = AEADAlgorithms.AES_SIV_CMAC_256.GetBytes();

        var c2sContext = new Byte[] { 0x00, 0x00, aeadBytes[0], aeadBytes[1], 0x00 };
        var s2cContext = new Byte[] { 0x00, 0x00, aeadBytes[0], aeadBytes[1], 0x01 };

        Assert.Multiple(() => {

            Assert.That(Bytes.ToHex(c2sContext), Is.EqualTo("0000000f00"),
                        "NTPv4 (0), AES-SIV-CMAC-256 (15), client-to-server (0)");

            Assert.That(Bytes.ToHex(s2cContext), Is.EqualTo("0000000f01"),
                        "NTPv4 (0), AES-SIV-CMAC-256 (15), server-to-client (1)");

            Assert.That(c2sContext[4], Is.Not.EqualTo(s2cContext[4]),
                        "the two directions must differ, or both keys would be identical");

        });

    }

    #endregion

}
