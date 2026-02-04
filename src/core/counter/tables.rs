use crate::error::{err, Error, Result};

#[derive(Debug, PartialEq)]
pub(crate) struct Sizage {
    pub hs: u32,
    pub ss: u32,
    pub ls: u32,
    pub fs: u32,
}

pub(crate) fn sizage(s: &str) -> Result<Sizage> {
    Ok(match s {
        // 4-char small count codes (max count 4095)
        "-A" => Sizage { hs: 2, ss: 2, fs: 4, ls: 0 }, // ControllerIdxSigs / GenericGroup
        "-B" => Sizage { hs: 2, ss: 2, fs: 4, ls: 0 }, // WitnessIdxSigs / MessageGroup
        "-C" => Sizage { hs: 2, ss: 2, fs: 4, ls: 0 }, // NonTransReceiptCouples / AttachedMaterialQuadlets
        "-D" => Sizage { hs: 2, ss: 2, fs: 4, ls: 0 }, // TransReceiptQuadruples / MessageDataGroup
        "-E" => Sizage { hs: 2, ss: 2, fs: 4, ls: 0 }, // FirstSeenReplayCouples / CombinedMaterialQuadlets
        "-F" => Sizage { hs: 2, ss: 2, fs: 4, ls: 0 }, // TransIdxSigGroups / MaterialGroup
        "-G" => Sizage { hs: 2, ss: 2, fs: 4, ls: 0 }, // SealSourceCouples / CESR native message signable
        "-H" => Sizage { hs: 2, ss: 2, fs: 4, ls: 0 }, // TransLastIdxSigGroups / Message group non-native
        "-I" => Sizage { hs: 2, ss: 2, fs: 4, ls: 0 }, // SealSourceTriples / Generic field map
        "-J" => Sizage { hs: 2, ss: 2, fs: 4, ls: 0 }, // SadPathSig / Generic list
        "-K" => Sizage { hs: 2, ss: 2, fs: 4, ls: 0 }, // SadPathSigGroup / IndexedControllerSigs
        "-L" => Sizage { hs: 2, ss: 2, fs: 4, ls: 0 }, // PathedMaterialQuadlets / IndexedWitnessSigs
        "-M" => Sizage { hs: 2, ss: 2, fs: 4, ls: 0 }, // NonTransReceiptCouples (spec name)
        "-N" => Sizage { hs: 2, ss: 2, fs: 4, ls: 0 }, // TransReceiptQuadruples (spec name)
        "-O" => Sizage { hs: 2, ss: 2, fs: 4, ls: 0 }, // FirstSeenReplayCouples (spec name)
        "-P" => Sizage { hs: 2, ss: 2, fs: 4, ls: 0 }, // PathedMaterialGroup
        "-Q" => Sizage { hs: 2, ss: 2, fs: 4, ls: 0 }, // DigestSealSingles
        "-R" => Sizage { hs: 2, ss: 2, fs: 4, ls: 0 }, // MerkleTreeRootSealSingles
        "-S" => Sizage { hs: 2, ss: 2, fs: 4, ls: 0 }, // EventSealSourceCouples
        "-T" => Sizage { hs: 2, ss: 2, fs: 4, ls: 0 }, // AnchoringEventSealTriples
        "-U" => Sizage { hs: 2, ss: 2, fs: 4, ls: 0 }, // LastEventSealSingles
        "-V" => Sizage { hs: 2, ss: 2, fs: 4, ls: 0 }, // BackerRegistrarSealCouples / AttachedMaterialQuadlets
        "-W" => Sizage { hs: 2, ss: 2, fs: 4, ls: 0 }, // TypedDigestSealCouples
        "-X" => Sizage { hs: 2, ss: 2, fs: 4, ls: 0 }, // TransIndexedSigGroups
        "-Y" => Sizage { hs: 2, ss: 2, fs: 4, ls: 0 }, // TransLastIndexedSigGroups
        "-Z" => Sizage { hs: 2, ss: 2, fs: 4, ls: 0 }, // ESSRPayload (TSP)
        "-a" => Sizage { hs: 2, ss: 2, fs: 4, ls: 0 }, // BlindedStateQuadruples
        "-b" => Sizage { hs: 2, ss: 2, fs: 4, ls: 0 }, // BoundBlindedStateSextuples
        "-c" => Sizage { hs: 2, ss: 2, fs: 4, ls: 0 }, // TypedBlindedMediaQuadruples
        "-0V" => Sizage { hs: 3, ss: 5, fs: 8, ls: 0 }, // BigAttachedMaterialQuadlets
        "--AAA" => Sizage { hs: 5, ss: 3, fs: 8, ls: 0 }, // KERIProtocolStack
        // Large count codes (8-char, 5-char count)
        "--AAB" => Sizage { hs: 5, ss: 3, fs: 8, ls: 0 }, // GenericGroupBig
        "--AAC" => Sizage { hs: 5, ss: 3, fs: 8, ls: 0 }, // MessageGroupBig
        "--AAD" => Sizage { hs: 5, ss: 3, fs: 8, ls: 0 }, // AttachedMaterialQuadletsBig
        "--AAE" => Sizage { hs: 5, ss: 3, fs: 8, ls: 0 }, // MessageDataGroupBig
        "--AAF" => Sizage { hs: 5, ss: 3, fs: 8, ls: 0 }, // CombinedMaterialQuadletsBig
        "--AAG" => Sizage { hs: 5, ss: 3, fs: 8, ls: 0 }, // MaterialGroupBig
        "--AAH" => Sizage { hs: 5, ss: 3, fs: 8, ls: 0 }, // MaterialQuadletsBig
        "--AAI" => Sizage { hs: 5, ss: 3, fs: 8, ls: 0 }, // Reserved
        "--AAJ" => Sizage { hs: 5, ss: 3, fs: 8, ls: 0 }, // Reserved
        "--AAK" => Sizage { hs: 5, ss: 3, fs: 8, ls: 0 }, // ControllerIdxSigsBig
        "--AAL" => Sizage { hs: 5, ss: 3, fs: 8, ls: 0 }, // WitnessIdxSigsBig
        "--AAM" => Sizage { hs: 5, ss: 3, fs: 8, ls: 0 }, // NonTransReceiptCouplesBig
        "--AAN" => Sizage { hs: 5, ss: 3, fs: 8, ls: 0 }, // TransReceiptQuadruplesBig
        "--AAO" => Sizage { hs: 5, ss: 3, fs: 8, ls: 0 }, // FirstSeenReplayCouplesBig
        "--AAP" => Sizage { hs: 5, ss: 3, fs: 8, ls: 0 }, // TransIdxSigGroupsBig
        "--AAQ" => Sizage { hs: 5, ss: 3, fs: 8, ls: 0 }, // SealSourceCouplesBig
        "--AAR" => Sizage { hs: 5, ss: 3, fs: 8, ls: 0 }, // TransLastIdxSigGroupsBig
        "--AAS" => Sizage { hs: 5, ss: 3, fs: 8, ls: 0 }, // SealSourceTriplesBig
        "--AAT" => Sizage { hs: 5, ss: 3, fs: 8, ls: 0 }, // SadPathSigBig
        "--AAU" => Sizage { hs: 5, ss: 3, fs: 8, ls: 0 }, // SadPathSigGroupBig
        "--AAV" => Sizage { hs: 5, ss: 3, fs: 8, ls: 0 }, // PathedMaterialQuadletsBig
        "--AAW" => Sizage { hs: 5, ss: 3, fs: 8, ls: 0 }, // TypedDigestSealCouplesBig
        "--AAX" => Sizage { hs: 5, ss: 3, fs: 8, ls: 0 }, // TransIndexedSigGroupsBig
        "--AAY" => Sizage { hs: 5, ss: 3, fs: 8, ls: 0 }, // TransLastIndexedSigGroupsBig
        "--AAZ" => Sizage { hs: 5, ss: 3, fs: 8, ls: 0 }, // ESSRPayloadBig (TSP)
        "--AAa" => Sizage { hs: 5, ss: 3, fs: 8, ls: 0 }, // BlindedStateQuadruplesBig
        "--AAb" => Sizage { hs: 5, ss: 3, fs: 8, ls: 0 }, // BoundBlindedStateSextuplesBig
        "--AAc" => Sizage { hs: 5, ss: 3, fs: 8, ls: 0 }, // TypedBlindedMediaQuadruplesBig
        // Protocol genus/version Op codes (8-char, 6-char soft for genus+version)
        "-_AAAB" => Sizage { hs: 2, ss: 6, fs: 8, ls: 0 }, // KERI ACDC CESR protocol genus version
        "-_AAAC" => Sizage { hs: 2, ss: 6, fs: 8, ls: 0 }, // Reserved protocol genus
        "-_AAAD" => Sizage { hs: 2, ss: 6, fs: 8, ls: 0 }, // Reserved protocol genus
        "-_AAAE" => Sizage { hs: 2, ss: 6, fs: 8, ls: 0 }, // Reserved protocol genus
        _ => return err!(Error::UnknownSizage(s.to_string())),
    })
}

pub(crate) fn hardage(s: &str) -> Result<u32> {
    match s {
        "-A" | "-B" | "-C" | "-D" | "-E" | "-F" | "-G" | "-H" | "-I" | "-J" | "-K" | "-L"
        | "-M" | "-N" | "-O" | "-P" | "-Q" | "-R" | "-S" | "-T" | "-U" | "-V" | "-W" | "-X"
        | "-Y" | "-Z" | "-a" | "-b" | "-c" => Ok(2),
        "-0" => Ok(3),
        "--" => Ok(5),
        "-_" => Ok(2), // Protocol genus/version Op codes
        _ => err!(Error::UnknownHardage(s.to_string())),
    }
}

pub(crate) fn bardage(b: &[u8]) -> Result<u32> {
    match b {
        // -A through -L: [62, 0-11]
        b">\x00" | b">\x01" | b">\x02" | b">\x03" | b">\x04" | b">\x05" | b">\x06" | b">\x07"
        | b">\x08" | b">\x09" | b">\x0a" | b">\x0b"
        // -M through -Z: [62, 12-25]
        | b">\x0c" | b">\x0d" | b">\x0e" | b">\x0f" | b">\x10" | b">\x11" | b">\x12" | b">\x13"
        | b">\x14" | b">\x15" | b">\x16" | b">\x17" | b">\x18" | b">\x19"
        // -a through -c: [62, 26-28]
        | b">\x1a" | b">\x1b" | b">\x1c" => Ok(2),
        b">4" => Ok(3),
        b">>" => Ok(5),
        b">?" => Ok(2), // -_ (protocol genus/version Op codes): [62, 63]
        _ => err!(Error::UnknownBardage(format!("{b:?}"))),
    }
}

#[allow(non_snake_case)]
#[allow(non_upper_case_globals)]
pub mod Codex {
    // 4-char small count codes (max count 4095)
    pub const ControllerIdxSigs: &str = "-A"; // Qualified Base64 Indexed Signature.
    pub const WitnessIdxSigs: &str = "-B"; // Qualified Base64 Indexed Signature.
    pub const NonTransReceiptCouples: &str = "-C"; // Composed Base64 Couple, pre+cig.
    pub const TransReceiptQuadruples: &str = "-D"; // Composed Base64 Quadruple, pre+snu+dig+sig.
    pub const FirstSeenReplayCouples: &str = "-E"; // Composed Base64 Couple, fnu+dts.
    pub const TransIdxSigGroups: &str = "-F"; // Composed Base64 Group, pre+snu+dig+ControllerIdxSigs group.
    pub const SealSourceCouples: &str = "-G"; // Composed Base64 couple, snu+dig of given delegators or issuers event
    pub const TransLastIdxSigGroups: &str = "-H"; // Composed Base64 Group, pre+ControllerIdxSigs group.
    pub const SealSourceTriples: &str = "-I"; // Composed Base64 triple, pre+snu+dig of anchoring source event
    pub const SadPathSig: &str = "-J"; // Composed Base64 Group path+TransIdxSigGroup of SAID of content
    pub const SadPathSigGroup: &str = "-K"; // Composed Base64 Group, root(path)+SaidPathCouples
    pub const PathedMaterialQuadlets: &str = "-L"; // Composed Grouped Pathed Material Quadlet (4 char each)
                                                   // Spec-aligned codes (overlapping with above but with different semantics in spec)
    pub const NonTransReceiptCouplesSpec: &str = "-M"; // Nontransferable identifier receipt couples pre+sig
    pub const TransReceiptQuadruplesSpec: &str = "-N"; // Transferable identifier receipt quadruples pre+snu+dig+sig
    pub const FirstSeenReplayCouplesSpec: &str = "-O"; // First seen replay couples fnu+dt
    pub const PathedMaterialGroup: &str = "-P"; // Pathed material group path+mixed-types
    pub const DigestSealSingles: &str = "-Q"; // Digest seal singles `dig`
    pub const MerkleTreeRootSealSingles: &str = "-R"; // Merkle Tree Root seal singles `rdig`
    pub const EventSealSourceCouples: &str = "-S"; // Issuer/Delegator/Transaction event seal source couple snu+dig
    pub const AnchoringEventSealTriples: &str = "-T"; // Anchoring event seal source triple pre+snu+dig
    pub const LastEventSealSingles: &str = "-U"; // Last event seal source singles `aid+dig`
    pub const AttachedMaterialQuadlets: &str = "-V"; // Backer registrar identifier seal couples `brid+dig`
    pub const TypedDigestSealCouples: &str = "-W"; // Typed digest seal couples `type+dig`
    pub const TransIndexedSigGroups: &str = "-X"; // Transferable indexed sig group pre+snu+dig+idx-controller-sig-groups
    pub const TransLastIndexedSigGroups: &str = "-Y"; // Transferable last indexed sig group pre+idx-controller-sig-groups
    pub const ESSRPayload: &str = "-Z"; // ESSR (TSP) Payload `version+messagtype+...`
    pub const BlindedStateQuadruples: &str = "-a"; // Blinded State quadruples dig+uuid+said+state
    pub const BoundBlindedStateSextuples: &str = "-b"; // Bound Blinded State Sextuples blid+uuid+said+state+bsnu+bsaid
    pub const TypedBlindedMediaQuadruples: &str = "-c"; // Typed and Blinded IANA media type quadruples blid+uuid+type+media
    pub const BigAttachedMaterialQuadlets: &str = "-0V"; // Composed Grouped Attached Material Quadlet (4 char each)
    pub const KERIProtocolStack: &str = "--AAA"; // KERI ACDC Protocol Stack CESR Version

    // 8-char large count codes (max count 262143)
    pub const GenericGroupBig: &str = "--AAB"; // Generic group big
    pub const MessageGroupBig: &str = "--AAC"; // Message group big
    pub const AttachedMaterialQuadletsBig: &str = "--AAD"; // Attached material quadlets big
    pub const MessageDataGroupBig: &str = "--AAE"; // Message data group big
    pub const CombinedMaterialQuadletsBig: &str = "--AAF"; // Combined material quadlets big
    pub const MaterialGroupBig: &str = "--AAG"; // Material group big
    pub const MaterialQuadletsBig: &str = "--AAH"; // Material quadlets big
    pub const ControllerIdxSigsBig: &str = "--AAK"; // Qualified Base64 Indexed Signature big
    pub const WitnessIdxSigsBig: &str = "--AAL"; // Qualified Base64 Indexed Signature big
    pub const NonTransReceiptCouplesBig: &str = "--AAM"; // Composed Base64 Couple big
    pub const TransReceiptQuadruplesBig: &str = "--AAN"; // Composed Base64 Quadruple big
    pub const FirstSeenReplayCouplesBig: &str = "--AAO"; // Composed Base64 Couple big
    pub const TransIdxSigGroupsBig: &str = "--AAP"; // Composed Base64 Group big
    pub const SealSourceCouplesBig: &str = "--AAQ"; // Composed Base64 couple big
    pub const TransLastIdxSigGroupsBig: &str = "--AAR"; // Composed Base64 Group big
    pub const SealSourceTriplesBig: &str = "--AAS"; // Composed Base64 triple big
    pub const SadPathSigBig: &str = "--AAT"; // Composed Base64 Group big
    pub const SadPathSigGroupBig: &str = "--AAU"; // Composed Base64 Group big
    pub const PathedMaterialQuadletsBig: &str = "--AAV"; // Composed Grouped Pathed Material big
    pub const TypedDigestSealCouplesBig: &str = "--AAW"; // Typed digest seal couples big
    pub const TransIndexedSigGroupsBig: &str = "--AAX"; // Trans indexed sig groups big
    pub const TransLastIndexedSigGroupsBig: &str = "--AAY"; // Trans last indexed sig groups big
    pub const ESSRPayloadBig: &str = "--AAZ"; // ESSR (TSP) Payload big
    pub const BlindedStateQuadruplesBig: &str = "--AAa"; // Blinded State quadruples big
    pub const BoundBlindedStateSextuplesBig: &str = "--AAb"; // Bound Blinded State Sextuples big
    pub const TypedBlindedMediaQuadruplesBig: &str = "--AAc"; // Typed and Blinded media quadruples big

    // Protocol genus/version Op codes (8-char, encodes genus major.minor and version major.minor)
    pub const KERIACDCGenusVersion: &str = "-_AAAB"; // KERI ACDC CESR protocol genus version
    pub const ProtocolGenusReserved1: &str = "-_AAAC"; // Reserved protocol genus
    pub const ProtocolGenusReserved2: &str = "-_AAAD"; // Reserved protocol genus
    pub const ProtocolGenusReserved3: &str = "-_AAAE"; // Reserved protocol genus
}

#[cfg(test)]
mod test {
    use crate::core::counter::tables as matter;
    use rstest::rstest;

    #[rstest]
    #[case("-A", 2)]
    #[case("-B", 2)]
    #[case("-C", 2)]
    #[case("-D", 2)]
    #[case("-E", 2)]
    #[case("-F", 2)]
    #[case("-G", 2)]
    #[case("-H", 2)]
    #[case("-I", 2)]
    #[case("-J", 2)]
    #[case("-K", 2)]
    #[case("-L", 2)]
    #[case("-M", 2)]
    #[case("-N", 2)]
    #[case("-O", 2)]
    #[case("-P", 2)]
    #[case("-Q", 2)]
    #[case("-R", 2)]
    #[case("-S", 2)]
    #[case("-T", 2)]
    #[case("-U", 2)]
    #[case("-V", 2)]
    #[case("-W", 2)]
    #[case("-X", 2)]
    #[case("-Y", 2)]
    #[case("-Z", 2)]
    #[case("-a", 2)]
    #[case("-b", 2)]
    #[case("-c", 2)]
    #[case("-0", 3)]
    #[case("--", 5)]
    #[case("-_", 2)]
    fn hardage(#[case] code: &str, #[case] hdg: u32) {
        assert_eq!(matter::hardage(code).unwrap(), hdg);
    }

    #[rstest]
    // -A through -L: [62, 0-11]
    #[case(&[62, 0], 2)]
    #[case(&[62, 1], 2)]
    #[case(&[62, 2], 2)]
    #[case(&[62, 3], 2)]
    #[case(&[62, 4], 2)]
    #[case(&[62, 5], 2)]
    #[case(&[62, 6], 2)]
    #[case(&[62, 7], 2)]
    #[case(&[62, 8], 2)]
    #[case(&[62, 9], 2)]
    #[case(&[62, 10], 2)]
    #[case(&[62, 11], 2)]
    // -M through -Z: [62, 12-25]
    #[case(&[62, 12], 2)]
    #[case(&[62, 13], 2)]
    #[case(&[62, 14], 2)]
    #[case(&[62, 15], 2)]
    #[case(&[62, 16], 2)]
    #[case(&[62, 17], 2)]
    #[case(&[62, 18], 2)]
    #[case(&[62, 19], 2)]
    #[case(&[62, 20], 2)]
    #[case(&[62, 21], 2)]
    #[case(&[62, 22], 2)]
    #[case(&[62, 23], 2)]
    #[case(&[62, 24], 2)]
    #[case(&[62, 25], 2)]
    // -a through -c: [62, 26-28]
    #[case(&[62, 26], 2)]
    #[case(&[62, 27], 2)]
    #[case(&[62, 28], 2)]
    // -0: [62, 52]
    #[case(&[62, 52], 3)]
    // --: [62, 62]
    #[case(&[62, 62], 5)]
    // -_: [62, 63] (protocol genus/version Op codes)
    #[case(&[62, 63], 2)]
    fn bardage(#[case] bard: &[u8], #[case] bdg: u32) {
        assert_eq!(matter::bardage(bard).unwrap(), bdg);
    }

    #[rstest]
    // 4-char small count codes
    #[case("-A", 2, 2, 4, 0)]
    #[case("-B", 2, 2, 4, 0)]
    #[case("-C", 2, 2, 4, 0)]
    #[case("-D", 2, 2, 4, 0)]
    #[case("-E", 2, 2, 4, 0)]
    #[case("-F", 2, 2, 4, 0)]
    #[case("-G", 2, 2, 4, 0)]
    #[case("-H", 2, 2, 4, 0)]
    #[case("-I", 2, 2, 4, 0)]
    #[case("-J", 2, 2, 4, 0)]
    #[case("-K", 2, 2, 4, 0)]
    #[case("-L", 2, 2, 4, 0)]
    #[case("-M", 2, 2, 4, 0)]
    #[case("-N", 2, 2, 4, 0)]
    #[case("-O", 2, 2, 4, 0)]
    #[case("-P", 2, 2, 4, 0)]
    #[case("-Q", 2, 2, 4, 0)]
    #[case("-R", 2, 2, 4, 0)]
    #[case("-S", 2, 2, 4, 0)]
    #[case("-T", 2, 2, 4, 0)]
    #[case("-U", 2, 2, 4, 0)]
    #[case("-V", 2, 2, 4, 0)]
    #[case("-W", 2, 2, 4, 0)]
    #[case("-X", 2, 2, 4, 0)]
    #[case("-Y", 2, 2, 4, 0)]
    #[case("-Z", 2, 2, 4, 0)]
    #[case("-a", 2, 2, 4, 0)]
    #[case("-b", 2, 2, 4, 0)]
    #[case("-c", 2, 2, 4, 0)]
    // 8-char count codes
    #[case("-0V", 3, 5, 8, 0)]
    #[case("--AAA", 5, 3, 8, 0)]
    #[case("--AAB", 5, 3, 8, 0)]
    #[case("--AAC", 5, 3, 8, 0)]
    #[case("--AAD", 5, 3, 8, 0)]
    #[case("--AAE", 5, 3, 8, 0)]
    #[case("--AAF", 5, 3, 8, 0)]
    #[case("--AAG", 5, 3, 8, 0)]
    #[case("--AAH", 5, 3, 8, 0)]
    #[case("--AAI", 5, 3, 8, 0)]
    #[case("--AAJ", 5, 3, 8, 0)]
    #[case("--AAK", 5, 3, 8, 0)]
    #[case("--AAL", 5, 3, 8, 0)]
    #[case("--AAM", 5, 3, 8, 0)]
    #[case("--AAN", 5, 3, 8, 0)]
    #[case("--AAO", 5, 3, 8, 0)]
    #[case("--AAP", 5, 3, 8, 0)]
    #[case("--AAQ", 5, 3, 8, 0)]
    #[case("--AAR", 5, 3, 8, 0)]
    #[case("--AAS", 5, 3, 8, 0)]
    #[case("--AAT", 5, 3, 8, 0)]
    #[case("--AAU", 5, 3, 8, 0)]
    #[case("--AAV", 5, 3, 8, 0)]
    #[case("--AAW", 5, 3, 8, 0)]
    #[case("--AAX", 5, 3, 8, 0)]
    #[case("--AAY", 5, 3, 8, 0)]
    #[case("--AAZ", 5, 3, 8, 0)]
    #[case("--AAa", 5, 3, 8, 0)]
    #[case("--AAb", 5, 3, 8, 0)]
    #[case("--AAc", 5, 3, 8, 0)]
    // Protocol genus/version Op codes
    #[case("-_AAAB", 2, 6, 8, 0)]
    #[case("-_AAAC", 2, 6, 8, 0)]
    #[case("-_AAAD", 2, 6, 8, 0)]
    #[case("-_AAAE", 2, 6, 8, 0)]
    fn sizage(
        #[case] code: &str,
        #[case] hs: u32,
        #[case] ss: u32,
        #[case] fs: u32,
        #[case] ls: u32,
    ) {
        let s = matter::sizage(code).unwrap();
        assert_eq!(s.hs, hs);
        assert_eq!(s.ss, ss);
        assert_eq!(s.fs, fs);
        assert_eq!(s.ls, ls);
    }

    #[rstest]
    // 4-char small count codes
    #[case(matter::Codex::ControllerIdxSigs, "-A")]
    #[case(matter::Codex::WitnessIdxSigs, "-B")]
    #[case(matter::Codex::NonTransReceiptCouples, "-C")]
    #[case(matter::Codex::TransReceiptQuadruples, "-D")]
    #[case(matter::Codex::FirstSeenReplayCouples, "-E")]
    #[case(matter::Codex::TransIdxSigGroups, "-F")]
    #[case(matter::Codex::SealSourceCouples, "-G")]
    #[case(matter::Codex::TransLastIdxSigGroups, "-H")]
    #[case(matter::Codex::SealSourceTriples, "-I")]
    #[case(matter::Codex::SadPathSig, "-J")]
    #[case(matter::Codex::SadPathSigGroup, "-K")]
    #[case(matter::Codex::PathedMaterialQuadlets, "-L")]
    #[case(matter::Codex::NonTransReceiptCouplesSpec, "-M")]
    #[case(matter::Codex::TransReceiptQuadruplesSpec, "-N")]
    #[case(matter::Codex::FirstSeenReplayCouplesSpec, "-O")]
    #[case(matter::Codex::PathedMaterialGroup, "-P")]
    #[case(matter::Codex::DigestSealSingles, "-Q")]
    #[case(matter::Codex::MerkleTreeRootSealSingles, "-R")]
    #[case(matter::Codex::EventSealSourceCouples, "-S")]
    #[case(matter::Codex::AnchoringEventSealTriples, "-T")]
    #[case(matter::Codex::LastEventSealSingles, "-U")]
    #[case(matter::Codex::AttachedMaterialQuadlets, "-V")]
    #[case(matter::Codex::TypedDigestSealCouples, "-W")]
    #[case(matter::Codex::TransIndexedSigGroups, "-X")]
    #[case(matter::Codex::TransLastIndexedSigGroups, "-Y")]
    #[case(matter::Codex::ESSRPayload, "-Z")]
    #[case(matter::Codex::BlindedStateQuadruples, "-a")]
    #[case(matter::Codex::BoundBlindedStateSextuples, "-b")]
    #[case(matter::Codex::TypedBlindedMediaQuadruples, "-c")]
    // 8-char large count codes
    #[case(matter::Codex::BigAttachedMaterialQuadlets, "-0V")]
    #[case(matter::Codex::KERIProtocolStack, "--AAA")]
    #[case(matter::Codex::GenericGroupBig, "--AAB")]
    #[case(matter::Codex::MessageGroupBig, "--AAC")]
    #[case(matter::Codex::AttachedMaterialQuadletsBig, "--AAD")]
    #[case(matter::Codex::MessageDataGroupBig, "--AAE")]
    #[case(matter::Codex::CombinedMaterialQuadletsBig, "--AAF")]
    #[case(matter::Codex::MaterialGroupBig, "--AAG")]
    #[case(matter::Codex::MaterialQuadletsBig, "--AAH")]
    #[case(matter::Codex::ControllerIdxSigsBig, "--AAK")]
    #[case(matter::Codex::WitnessIdxSigsBig, "--AAL")]
    #[case(matter::Codex::NonTransReceiptCouplesBig, "--AAM")]
    #[case(matter::Codex::TransReceiptQuadruplesBig, "--AAN")]
    #[case(matter::Codex::FirstSeenReplayCouplesBig, "--AAO")]
    #[case(matter::Codex::TransIdxSigGroupsBig, "--AAP")]
    #[case(matter::Codex::SealSourceCouplesBig, "--AAQ")]
    #[case(matter::Codex::TransLastIdxSigGroupsBig, "--AAR")]
    #[case(matter::Codex::SealSourceTriplesBig, "--AAS")]
    #[case(matter::Codex::SadPathSigBig, "--AAT")]
    #[case(matter::Codex::SadPathSigGroupBig, "--AAU")]
    #[case(matter::Codex::PathedMaterialQuadletsBig, "--AAV")]
    #[case(matter::Codex::TypedDigestSealCouplesBig, "--AAW")]
    #[case(matter::Codex::TransIndexedSigGroupsBig, "--AAX")]
    #[case(matter::Codex::TransLastIndexedSigGroupsBig, "--AAY")]
    #[case(matter::Codex::ESSRPayloadBig, "--AAZ")]
    #[case(matter::Codex::BlindedStateQuadruplesBig, "--AAa")]
    #[case(matter::Codex::BoundBlindedStateSextuplesBig, "--AAb")]
    #[case(matter::Codex::TypedBlindedMediaQuadruplesBig, "--AAc")]
    // Protocol genus/version Op codes
    #[case(matter::Codex::KERIACDCGenusVersion, "-_AAAB")]
    #[case(matter::Codex::ProtocolGenusReserved1, "-_AAAC")]
    #[case(matter::Codex::ProtocolGenusReserved2, "-_AAAD")]
    #[case(matter::Codex::ProtocolGenusReserved3, "-_AAAE")]
    fn codex(#[case] code: &str, #[case] value: &str) {
        assert_eq!(code, value);
    }

    #[test]
    fn unhappy_paths() {
        assert!(matter::sizage("CESR").is_err());
        assert!(matter::bardage(&[63, 0]).is_err());
    }
}
