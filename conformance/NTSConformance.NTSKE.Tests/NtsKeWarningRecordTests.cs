using NUnit.Framework;

using NTSConformance.Core;
using NTSConformance.Core.RawNtsKe;

using org.GraphDefined.Vanaheimr.Norn.NTS;

namespace NTSConformance.NTSKE.Tests;

/// <summary>
/// RFC 8915 §4.1.4, the Warning record — the one NTS-KE record type that is easy to read as
/// advisory and is not.
///
/// The section is three sentences long, and the third is the whole of it:
/// "Unrecognized warning codes MUST be treated as errors." The IANA "Network Time Security
/// Warning Codes" registry has never assigned a single code — every value from 0 to 32767 is
/// unassigned, and 32768 upwards is reserved for private use — so today <em>every</em> warning
/// code is unrecognized, and a client that receives one has no conformant option but to fail
/// the key exchange.
///
/// That reading is not an interpretation of a corner case. A record type whose entire purpose
/// is to be defined later can only be safe if clients fail closed on the codes they have never
/// heard of; a client that logs an unknown warning and carries on is exactly the client that
/// would ignore the first code IANA ever assigns.
///
/// Norn's server never sends a Warning record, so the only way to put one in front of its
/// client is to build the record stream here. The bytes come from
/// <see cref="RawNtsKeCodec"/> and are handed to Norn's own parser and validator, which is the
/// same path a real server's response takes.
/// </summary>
[TestFixture]
public class NtsKeWarningRecordTests
{

    /// <summary>
    /// An arbitrary unassigned warning code. Every code is unassigned; this one is unremarkable.
    /// </summary>
    private const UInt16 SomeWarningCode = 1;

    private const UInt16 AeadAesSivCmac256 = 15;


    /// <summary>
    /// A response that is complete and valid in every other respect, so that anything the
    /// validator objects to has to be the warning.
    /// </summary>
    private static IEnumerable<NTSKE_Record> ServerResponse(params RawNtsKeRecord[] extraRecords)
    {

        var records = new List<RawNtsKeRecord> {
                          RawNtsKeRecord.NextProtocolNegotiation(RawNtsKeNextProtocols.Ntpv4),
                          RawNtsKeRecord.AeadAlgorithmNegotiation(AeadAesSivCmac256)
                      };

        records.AddRange(extraRecords);
        records.Add(RawNtsKeRecord.NewCookieForNtpv4([ 0x01, 0x02, 0x03, 0x04 ]));
        records.Add(RawNtsKeRecord.EndOfMessage());

        var encoded = RawNtsKeCodec.Encode(records);

        if (!NTSKE_Record.TryParse(encoded, out var parsed, out var errorResponse))
        {
            Assert.Fail($"Norn could not parse the reference encoder's record stream: {errorResponse}");
            return [];
        }

        return parsed;

    }


    /// <summary>
    /// The baseline. Without this passing, a validator that rejected everything would look
    /// conformant in the test below.
    /// </summary>
    [Test]
    public void WithoutAWarningRecord_TheResponseIsAccepted()
    {

        var accepted = NTSKERecordValidator.ValidateServerResponse(
                           ServerResponse(),
                           out var errorMessage,
                           out _
                       );

        Assert.That(accepted, Is.True, $"the baseline response should validate: {errorMessage}");

    }


    /// <summary>
    /// RFC 8915 §4.1.4: "Unrecognized warning codes MUST be treated as errors."
    ///
    /// The response is otherwise perfectly good — negotiated protocol, negotiated algorithm,
    /// a cookie — which is the case that matters. A client that only fails when something else
    /// is already wrong is not implementing this rule.
    /// </summary>
    [Test]
    public void AnUnrecognizedWarningCode_IsTreatedAsAnError()
    {

        var accepted = NTSKERecordValidator.ValidateServerResponse(
                           ServerResponse(RawNtsKeRecord.Warning(SomeWarningCode)),
                           out var errorMessage,
                           out var errorCategory
                       );

        Assert.Multiple(() => {

            Assert.That(accepted,
                        Is.False,
                        $"warning code {SomeWarningCode} is unassigned in the IANA registry — as " +
                        $"every warning code currently is — so the key exchange must fail rather " +
                        $"than proceed with the session keys");

            Assert.That(errorCategory,
                        Is.EqualTo(NTSKEErrorCategory.ServerWarning),
                        $"the refusal must be attributable to the warning: {errorMessage}");

        });

    }


    /// <summary>
    /// Failing is not enough on its own — the code has to reach whoever has to act on it.
    /// A key exchange refused with "something was wrong" is a support case; refused with the
    /// code the server sent is a five-minute answer.
    /// </summary>
    [Test]
    public void TheWarning_IsReportedAndNotMerelyRefused()
    {

        NTSKERecordValidator.ValidateServerResponse(
            ServerResponse(RawNtsKeRecord.Warning(SomeWarningCode)),
            out var errorMessage,
            out _,
            out var warningMessages
        );

        Assert.Multiple(() => {

            Assert.That(warningMessages,
                        Is.Not.Empty,
                        "the warning record must be surfaced, not just counted as a failure");

            Assert.That(errorMessage,
                        Does.Contain("arning"),
                        $"the error should say a warning caused it: {errorMessage}");

        });

    }


    /// <summary>
    /// The record type is understood, which is a separate question from what to do with the
    /// code inside it. Reporting a Warning record as an unknown critical record type would
    /// send whoever reads the message looking for a record type that does not exist, instead
    /// of at a warning code that does.
    /// </summary>
    [Test]
    public void AWarningRecord_IsNotMistakenForAnUnknownRecordType()
    {

        NTSKERecordValidator.ValidateServerResponse(
            ServerResponse(RawNtsKeRecord.Warning(SomeWarningCode)),
            out _,
            out var errorCategory
        );

        Assert.That(errorCategory,
                    Is.Not.EqualTo(NTSKEErrorCategory.UnknownCriticalRecord),
                    "Warning is record type 3 and RFC 8915 §4.1.4 defines it — it is the code " +
                    "that is unrecognized, not the record");

    }

}
