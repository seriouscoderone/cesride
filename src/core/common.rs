use crate::data::Value;
use crate::error::{err, Error, Result};

use lazy_static::lazy_static;
use regex::Regex;

#[derive(Debug, Clone, PartialEq)]
pub struct SizeifyResult {
    pub raw: Vec<u8>,
    pub ident: String,
    pub kind: String,
    pub ked: Value,
    pub version: Version,
}

#[derive(Debug, Clone, PartialEq)]
pub struct DeversifyResult {
    pub ident: String,
    pub kind: String,
    pub version: Version,
    pub size: u32,
}

/// Version 2.XX deversify result with additional genus version
#[derive(Debug, Clone, PartialEq)]
pub struct DeversifyResultV2 {
    pub ident: String,
    pub kind: String,
    pub version: Version,
    pub genus: Version,
    pub size: u32,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SniffResult {
    pub ident: String,
    pub kind: String,
    pub version: Version,
    pub size: u32,
}

/// Version 2.XX sniff result with additional genus version
#[derive(Debug, Clone, PartialEq)]
pub struct SniffResultV2 {
    pub ident: String,
    pub kind: String,
    pub version: Version,
    pub genus: Version,
    pub size: u32,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Version {
    pub major: u8,
    pub minor: u16,
}

#[allow(non_snake_case)]
pub mod Serialage {
    pub const JSON: &str = "JSON";
}

#[allow(non_snake_case)]
pub mod Identage {
    pub const ACDC: &str = "ACDC";
    pub const KERI: &str = "KERI";
}

#[allow(non_snake_case)]
#[allow(non_upper_case_globals)]
pub mod Ilkage {
    pub const icp: &str = "icp";
    pub const rot: &str = "rot";
    pub const ixn: &str = "ixn";
    pub const dip: &str = "dip";
    pub const drt: &str = "drt";
    pub const rct: &str = "rct";
    pub const ksn: &str = "ksn";
    pub const qry: &str = "qry";
    pub const rpy: &str = "rpy";
    pub const exn: &str = "exn";
    pub const pro: &str = "pro";
    pub const bar: &str = "bar";
    pub const vcp: &str = "vcp";
    pub const vrt: &str = "vrt";
    pub const iss: &str = "iss";
    pub const rev: &str = "rev";
    pub const bis: &str = "bis";
    pub const brv: &str = "brv";
}

#[allow(non_snake_case)]
#[allow(non_upper_case_globals)]
pub mod Tierage {
    pub(crate) const min: &str = "min";
    pub const low: &str = "low";
    pub const med: &str = "med";
    pub const high: &str = "high";
}

#[allow(non_snake_case)]
#[allow(non_upper_case_globals)]
pub mod Ids {
    pub const dollar: &str = "$id";
    pub const at: &str = "@id";
    pub const id: &str = "id";
    pub const i: &str = "i";
    pub const d: &str = "d";
    pub const t: &str = "t";
    pub const k: &str = "k";
    pub const n: &str = "n";
    pub const b: &str = "b";
    pub const a: &str = "a";
    pub const s: &str = "s";
    pub const f: &str = "f";
    pub const v: &str = "v";
    pub const kt: &str = "kt";
    pub const nt: &str = "nt";
    pub const di: &str = "di";
}

// Version 1.XX format: PPPPvvKKKKllllll_ (17 chars)
const REVER_STRING: &str = "(?P<ident>[A-Z]{4})(?P<major>[0-9a-f])(?P<minor>[0-9a-f])(?P<kind>[A-Z]{4})(?P<size>[0-9a-f]{6})_";

// Version 2.XX format: PPPPMmmGggKKKKBBBB. (19 chars)
// M = major version (base64), mm = minor version (base64)
// G = genus major (base64), gg = genus minor (base64)
// BBBB = size in base64 notation
const REVER_STRING_V2: &str = "(?P<ident>[A-Z]{4})(?P<major>[A-Za-z0-9_-])(?P<minor>[A-Za-z0-9_-]{2})(?P<genusmaj>[A-Za-z0-9_-])(?P<genusmin>[A-Za-z0-9_-]{2})(?P<kind>[A-Z]{4})(?P<size>[A-Za-z0-9_-]{4})\\.";

const IDENTS: &[&str] = &[Identage::ACDC, Identage::KERI];
const SERIALS: &[&str] = &[Serialage::JSON];

pub(crate) const DUMMY: u8 = b'#';

pub const CURRENT_VERSION: &Version = &Version { major: 1, minor: 0 };
pub const VERSION_2: &Version = &Version { major: 2, minor: 0 };

const MAXIMUM_START_SIZE: usize = 12;
pub(crate) const VERSION_FULL_SIZE: usize = 17;
pub(crate) const VERSION_FULL_SIZE_V2: usize = 19;
pub(crate) const MINIMUM_SNIFF_SIZE: usize = MAXIMUM_START_SIZE + VERSION_FULL_SIZE;
pub(crate) const MINIMUM_SNIFF_SIZE_V2: usize = MAXIMUM_START_SIZE + VERSION_FULL_SIZE_V2;

// Base64 URL-safe alphabet for version 2.0 encoding
const B64_CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Convert a base64 character to its numeric value (0-63)
fn b64_to_num(c: char) -> Result<u32> {
    match c {
        'A'..='Z' => Ok(c as u32 - 'A' as u32),
        'a'..='z' => Ok(c as u32 - 'a' as u32 + 26),
        '0'..='9' => Ok(c as u32 - '0' as u32 + 52),
        '-' => Ok(62),
        '_' => Ok(63),
        _ => err!(Error::Validation(format!("invalid base64 character: {c}"))),
    }
}

/// Convert a numeric value (0-63) to a base64 character
fn num_to_b64(n: u32) -> Result<char> {
    if n > 63 {
        return err!(Error::Validation(format!("value {n} exceeds base64 range (0-63)")));
    }
    Ok(B64_CHARS[n as usize] as char)
}

/// Decode a 3-character base64 string to a (major, minor) version tuple
/// First char is major (0-63), next two chars are minor (0-4095)
fn decode_b64_version(s: &str) -> Result<(u8, u16)> {
    if s.len() != 3 {
        return err!(Error::Validation(format!(
            "expected 3 character version string, got {}",
            s.len()
        )));
    }
    let chars: Vec<char> = s.chars().collect();
    let major = b64_to_num(chars[0])? as u8;
    let minor_high = b64_to_num(chars[1])?;
    let minor_low = b64_to_num(chars[2])?;
    let minor = (minor_high * 64 + minor_low) as u16;
    Ok((major, minor))
}

/// Encode a (major, minor) version tuple to a 3-character base64 string
fn encode_b64_version(major: u8, minor: u16) -> Result<String> {
    if major > 63 {
        return err!(Error::Validation(format!(
            "major version {major} exceeds base64 range (0-63)"
        )));
    }
    if minor > 4095 {
        return err!(Error::Validation(format!(
            "minor version {minor} exceeds base64 range (0-4095)"
        )));
    }
    let m = num_to_b64(major as u32)?;
    let minor_high = num_to_b64((minor / 64) as u32)?;
    let minor_low = num_to_b64((minor % 64) as u32)?;
    Ok(format!("{m}{minor_high}{minor_low}"))
}

/// Decode a 4-character base64 size to a u32
fn decode_b64_size(s: &str) -> Result<u32> {
    if s.len() != 4 {
        return err!(Error::Validation(format!(
            "expected 4 character size string, got {}",
            s.len()
        )));
    }
    let chars: Vec<char> = s.chars().collect();
    let mut result: u32 = 0;
    for c in chars {
        result = result * 64 + b64_to_num(c)?;
    }
    Ok(result)
}

/// Encode a u32 size to a 4-character base64 string
fn encode_b64_size(size: u32) -> Result<String> {
    if size > 16_777_215 {
        // 64^4 - 1
        return err!(Error::Validation(format!("size {size} exceeds 4-char base64 range")));
    }
    let c0 = num_to_b64(size / (64 * 64 * 64))?;
    let c1 = num_to_b64((size / (64 * 64)) % 64)?;
    let c2 = num_to_b64((size / 64) % 64)?;
    let c3 = num_to_b64(size % 64)?;
    Ok(format!("{c0}{c1}{c2}{c3}"))
}

pub fn deversify(vs: &str) -> Result<DeversifyResult> {
    lazy_static! {
        static ref REVER: Regex = Regex::new(REVER_STRING).unwrap();
    };

    if REVER.is_match(vs) {
        let ident = REVER.replace_all(vs, "$ident").to_string();
        let major = u8::from_str_radix(&REVER.replace_all(vs, "$major"), 16)?;
        let minor = u16::from_str_radix(&REVER.replace_all(vs, "$minor"), 16)?;
        let kind = REVER.replace_all(vs, "$kind").to_string();
        let size = u32::from_str_radix(&REVER.replace_all(vs, "$size"), 16)?;

        if !IDENTS.contains(&ident.as_str()) {
            return err!(Error::Validation(format!("invalid ident {ident}")));
        }

        if !SERIALS.contains(&kind.as_str()) {
            return err!(Error::Validation(format!("invalid serialization kind {kind}")));
        }

        return Ok(DeversifyResult { ident, kind, version: Version { major, minor }, size });
    }

    err!(Error::Validation(format!("invalid version string {vs}")))
}

/// Deversify a Version 2.XX version string
/// Format: PPPPMmmGggKKKKBBBB. (19 chars)
pub fn deversify_v2(vs: &str) -> Result<DeversifyResultV2> {
    lazy_static! {
        static ref REVER_V2: Regex = Regex::new(REVER_STRING_V2).unwrap();
    };

    if REVER_V2.is_match(vs) {
        let ident = REVER_V2.replace_all(vs, "$ident").to_string();
        let major_str = REVER_V2.replace_all(vs, "$major").to_string();
        let minor_str = REVER_V2.replace_all(vs, "$minor").to_string();
        let genusmaj_str = REVER_V2.replace_all(vs, "$genusmaj").to_string();
        let genusmin_str = REVER_V2.replace_all(vs, "$genusmin").to_string();
        let kind = REVER_V2.replace_all(vs, "$kind").to_string();
        let size_str = REVER_V2.replace_all(vs, "$size").to_string();

        // Decode version: major is 1 char, minor is 2 chars
        let version_str = format!("{major_str}{minor_str}");
        let (major, minor) = decode_b64_version(&version_str)?;

        // Decode genus version: genusmaj is 1 char, genusmin is 2 chars
        let genus_str = format!("{genusmaj_str}{genusmin_str}");
        let (genus_major, genus_minor) = decode_b64_version(&genus_str)?;

        // Decode size
        let size = decode_b64_size(&size_str)?;

        if !IDENTS.contains(&ident.as_str()) {
            return err!(Error::Validation(format!("invalid ident {ident}")));
        }

        if !SERIALS.contains(&kind.as_str()) {
            return err!(Error::Validation(format!("invalid serialization kind {kind}")));
        }

        return Ok(DeversifyResultV2 {
            ident,
            kind,
            version: Version { major, minor },
            genus: Version { major: genus_major, minor: genus_minor },
            size,
        });
    }

    err!(Error::Validation(format!("invalid version 2.0 string {vs}")))
}

pub fn sizeify(ked: &Value, kind: Option<&str>) -> Result<SizeifyResult> {
    lazy_static! {
        static ref REVER: Regex = Regex::new(REVER_STRING).unwrap();
    };

    if !ked.to_map()?.contains_key("v") {
        return err!(Error::Value("missing or empty version string".to_string()));
    }

    let result = deversify(&ked["v"].to_string()?)?;
    if result.version != *CURRENT_VERSION {
        return err!(Error::Value(format!(
            "unsupported version {}.{}",
            result.version.major, result.version.minor
        )));
    }

    let kind = if let Some(kind) = kind { kind.to_string() } else { result.kind };

    if !SERIALS.contains(&kind.as_str()) {
        return err!(Error::Value(format!("invalid serialization kind {kind}")));
    }

    let raw = &dumps(ked, Some(&kind))?;
    let size = raw.len();

    let start = match REVER.shortest_match(&String::from_utf8(raw.clone())?) {
        Some(m) => m - VERSION_FULL_SIZE,
        // unreachable - deversify has been called which ensures this will match
        None => return err!(Error::Value(format!("invalid version string in raw = {raw:?}"))),
    };

    if start > MAXIMUM_START_SIZE {
        return err!(Error::Value(format!(
            "invalid version string in raw = {raw:?} start = {start}"
        )));
    }

    let fore = raw[..start].to_vec();
    let mut back = raw[start + VERSION_FULL_SIZE..].to_vec();
    let vs = versify(Some(&result.ident), Some(&result.version), Some(&kind), Some(size as u32))?;

    let mut raw = fore;
    raw.append(&mut vs.as_bytes().to_vec());
    raw.append(&mut back);

    if raw.len() != size {
        // unreachable as we constructed this
        return err!(Error::Value(format!("malformed version string size, version string = {vs}")));
    }

    let mut ked = ked.clone();
    ked["v"] = dat!(&vs);

    Ok(SizeifyResult { raw, ident: result.ident, kind, ked, version: result.version })
}

pub fn versify(
    ident: Option<&str>,
    version: Option<&Version>,
    kind: Option<&str>,
    size: Option<u32>,
) -> Result<String> {
    let ident = ident.unwrap_or(Identage::KERI);
    let version = version.unwrap_or(CURRENT_VERSION);
    let kind = kind.unwrap_or(Serialage::JSON);
    let size = size.unwrap_or(0);

    if !IDENTS.contains(&ident) {
        return err!(Error::Validation(format!("invalid ident {ident}")));
    }

    if !SERIALS.contains(&kind) {
        return err!(Error::Validation(format!("invalid serialization kind {kind}")));
    }

    // v1.0 format has 1 hex digit for minor, so truncate to 0-15
    let minor = (version.minor & 0x0F) as u8;

    Ok(format!("{ident}{major:01x}{minor:01x}{kind}{size:06x}_", major = version.major,))
}

/// Create a Version 2.XX version string
/// Format: PPPPMmmGggKKKKBBBB. (19 chars)
pub fn versify_v2(
    ident: Option<&str>,
    version: Option<&Version>,
    genus: Option<&Version>,
    kind: Option<&str>,
    size: Option<u32>,
) -> Result<String> {
    let ident = ident.unwrap_or(Identage::KERI);
    let version = version.unwrap_or(VERSION_2);
    let genus = genus.unwrap_or(VERSION_2);
    let kind = kind.unwrap_or(Serialage::JSON);
    let size = size.unwrap_or(0);

    if !IDENTS.contains(&ident) {
        return err!(Error::Validation(format!("invalid ident {ident}")));
    }

    if !SERIALS.contains(&kind) {
        return err!(Error::Validation(format!("invalid serialization kind {kind}")));
    }

    let version_str = encode_b64_version(version.major, version.minor)?;
    let genus_str = encode_b64_version(genus.major, genus.minor)?;
    let size_str = encode_b64_size(size)?;

    Ok(format!("{ident}{version_str}{genus_str}{kind}{size_str}."))
}

pub(crate) fn loads(raw: &[u8], size: Option<u32>, kind: Option<&str>) -> Result<Value> {
    let kind = kind.unwrap_or(Serialage::JSON);

    if let Some(size) = size {
        match kind {
            Serialage::JSON => {
                let v: serde_json::Value =
                    serde_json::from_str(&String::from_utf8(raw[..(size as usize)].to_vec())?)?;
                Ok(Value::from(&v))
            }
            _ => err!(Error::Validation(format!("invalid serialization kind {kind}"))),
        }
    } else {
        match kind {
            Serialage::JSON => {
                let v: serde_json::Value = serde_json::from_str(&String::from_utf8(raw.to_vec())?)?;
                Ok(Value::from(&v))
            }
            _ => err!(Error::Validation(format!("invalid serialization kind {kind}"))),
        }
    }
}

pub(crate) fn dumps(ked: &Value, kind: Option<&str>) -> Result<Vec<u8>> {
    let kind = kind.unwrap_or(Serialage::JSON);
    match kind {
        Serialage::JSON => Ok(ked.to_json()?.as_bytes().to_vec()),
        _ => err!(Error::Value(format!("invalid serialization kind = {kind}"))),
    }
}

pub fn sniff(raw: &[u8]) -> Result<SniffResult> {
    lazy_static! {
        static ref REVER: Regex = Regex::new(REVER_STRING).unwrap();
    };

    if raw.len() < MINIMUM_SNIFF_SIZE {
        return err!(Error::Value(format!(
            "need more bytes than {bytes} to sniff",
            bytes = raw.len()
        )));
    }

    let raw = &String::from_utf8(raw.to_vec())?;
    let start = match REVER.shortest_match(raw) {
        Some(m) => m - VERSION_FULL_SIZE,
        None => return err!(Error::Value(format!("invalid version string in raw = {raw:?}"))),
    };

    if start > MAXIMUM_START_SIZE {
        return err!(Error::Value(format!(
            "invalid version string in raw = {raw:?} start = {start}"
        )));
    }

    let vs = &raw[start..(start + VERSION_FULL_SIZE)];

    let ident = REVER.replace_all(vs, "$ident").to_string();
    let major = u8::from_str_radix(&REVER.replace_all(vs, "$major"), 16)?;
    let minor = u16::from_str_radix(&REVER.replace_all(vs, "$minor"), 16)?;
    let kind = REVER.replace_all(vs, "$kind").to_string();
    let size = u32::from_str_radix(&REVER.replace_all(vs, "$size"), 16)?;
    let version = Version { major, minor };

    if !SERIALS.contains(&kind.as_str()) {
        return err!(Error::Validation(format!("invalid serialization kind {kind}")));
    }

    Ok(SniffResult { ident, kind, version, size })
}

/// Sniff a Version 2.XX stream for its version string
/// Format: PPPPMmmGggKKKKBBBB. (19 chars)
pub fn sniff_v2(raw: &[u8]) -> Result<SniffResultV2> {
    lazy_static! {
        static ref REVER_V2: Regex = Regex::new(REVER_STRING_V2).unwrap();
    };

    if raw.len() < MINIMUM_SNIFF_SIZE_V2 {
        return err!(Error::Value(format!(
            "need more bytes than {bytes} to sniff v2",
            bytes = raw.len()
        )));
    }

    let raw_str = String::from_utf8(raw.to_vec())?;
    let start = match REVER_V2.shortest_match(&raw_str) {
        Some(m) => m - VERSION_FULL_SIZE_V2,
        None => return err!(Error::Value("invalid v2 version string in raw".to_string())),
    };

    if start > MAXIMUM_START_SIZE {
        return err!(Error::Value(format!("invalid v2 version string start = {start}")));
    }

    let vs = &raw_str[start..(start + VERSION_FULL_SIZE_V2)];
    let result = deversify_v2(vs)?;

    Ok(SniffResultV2 {
        ident: result.ident,
        kind: result.kind,
        version: result.version,
        genus: result.genus,
        size: result.size,
    })
}

/// Try to sniff either v1 or v2 version string, returning the appropriate result
#[derive(Debug, Clone, PartialEq)]
pub enum SniffResultAny {
    V1(SniffResult),
    V2(SniffResultV2),
}

pub fn sniff_any(raw: &[u8]) -> Result<SniffResultAny> {
    // Try v2 first (ends with '.')
    if let Ok(result) = sniff_v2(raw) {
        return Ok(SniffResultAny::V2(result));
    }
    // Fall back to v1 (ends with '_')
    if let Ok(result) = sniff(raw) {
        return Ok(SniffResultAny::V1(result));
    }
    err!(Error::Value("no valid version string found".to_string()))
}

#[cfg(test)]
mod test {
    use crate::core::common;
    use rstest::rstest;

    #[test]
    fn loads() {
        let raw = &dat!({}).to_json().unwrap().as_bytes().to_vec();
        assert!(common::loads(raw, None, None).is_ok());
    }

    #[test]
    fn sniff_unhappy_paths() {
        assert!(common::sniff(&[]).is_err()); // minimum 29 octets
        assert!(common::sniff(
            dat!({"v":"version string must be valid!"}).to_json().unwrap().as_bytes()
        )
        .is_err());
        assert!(common::sniff(
            dat!({"i":"needs to start within 12 characters!","v":"KERI10JSON000000_"})
                .to_json()
                .unwrap()
                .as_bytes()
        )
        .is_err());
        assert!(common::sniff(dat!({"v":"KERI10ABCD000000_","confusing but necessary filler":"hmm...maybe a 12 octet magic prefix?"}).to_json().unwrap().as_bytes()).is_err());
        // needs to have a valid serialization kind
    }

    #[test]
    fn loads_unhappy_paths() {
        let raw = &dat!({}).to_json().unwrap().as_bytes().to_vec();
        assert!(common::loads(raw, None, Some("CESR")).is_err());
        assert!(common::loads(raw, Some(1024), Some("CESR")).is_err());
    }

    #[test]
    fn sizeify_unhappy_paths() {
        assert!(common::sizeify(&dat!({}), None).is_err());
        assert!(common::sizeify(&dat!({"v":"KERIffJSON000000_"}), None).is_err());
        assert!(common::sizeify(&dat!({"v":"KERI10JSON000000_"}), Some("CESR")).is_err());
        assert!(common::sizeify(&dat!({"i":"filler entry","v":"KERI10JSON000000_"}), None).is_err());
    }

    #[test]
    fn versify_unhappy_paths() {
        assert!(common::versify(Some("CESR"), None, None, None).is_err());
        assert!(common::versify(None, None, Some("CESR"), None).is_err());
    }

    #[rstest]
    fn deversify_unhappy_paths(
        #[values("CESR10JSON000000_", "KERI10CESR000000_", "KERIXXJSON000000_")] vs: &str,
    ) {
        assert!(common::deversify(vs).is_err());
    }

    #[test]
    fn dumps_unhappy_paths() {
        assert!(common::dumps(&dat!({}), Some("CESR")).is_err());
    }

    // Version 2.0 tests

    #[test]
    fn b64_conversion() {
        // Test base64 number conversion
        assert_eq!(common::b64_to_num('A').unwrap(), 0);
        assert_eq!(common::b64_to_num('Z').unwrap(), 25);
        assert_eq!(common::b64_to_num('a').unwrap(), 26);
        assert_eq!(common::b64_to_num('z').unwrap(), 51);
        assert_eq!(common::b64_to_num('0').unwrap(), 52);
        assert_eq!(common::b64_to_num('9').unwrap(), 61);
        assert_eq!(common::b64_to_num('-').unwrap(), 62);
        assert_eq!(common::b64_to_num('_').unwrap(), 63);

        assert_eq!(common::num_to_b64(0).unwrap(), 'A');
        assert_eq!(common::num_to_b64(25).unwrap(), 'Z');
        assert_eq!(common::num_to_b64(26).unwrap(), 'a');
        assert_eq!(common::num_to_b64(51).unwrap(), 'z');
        assert_eq!(common::num_to_b64(52).unwrap(), '0');
        assert_eq!(common::num_to_b64(61).unwrap(), '9');
        assert_eq!(common::num_to_b64(62).unwrap(), '-');
        assert_eq!(common::num_to_b64(63).unwrap(), '_');
    }

    #[test]
    fn b64_version_encoding() {
        // Version 2.0 -> CAA (major=2, minor=0)
        let (major, minor) = common::decode_b64_version("CAA").unwrap();
        assert_eq!(major, 2);
        assert_eq!(minor, 0);

        let encoded = common::encode_b64_version(2, 0).unwrap();
        assert_eq!(encoded, "CAA");

        // Version 2.16 -> CAQ (major=2, minor=16)
        let (major, minor) = common::decode_b64_version("CAQ").unwrap();
        assert_eq!(major, 2);
        assert_eq!(minor, 16);

        let encoded = common::encode_b64_version(2, 16).unwrap();
        assert_eq!(encoded, "CAQ");

        // Version 1.0 -> BAA
        let (major, minor) = common::decode_b64_version("BAA").unwrap();
        assert_eq!(major, 1);
        assert_eq!(minor, 0);
    }

    #[test]
    fn b64_size_encoding() {
        // Size 0 -> AAAA
        assert_eq!(common::encode_b64_size(0).unwrap(), "AAAA");
        assert_eq!(common::decode_b64_size("AAAA").unwrap(), 0);

        // Size 1234
        let size = 1234u32;
        let encoded = common::encode_b64_size(size).unwrap();
        assert_eq!(common::decode_b64_size(&encoded).unwrap(), size);

        // Max size (64^4 - 1 = 16777215)
        let max_size = 16_777_215u32;
        let encoded = common::encode_b64_size(max_size).unwrap();
        assert_eq!(encoded, "____");
        assert_eq!(common::decode_b64_size(&encoded).unwrap(), max_size);
    }

    #[test]
    fn versify_v2_roundtrip() {
        let version = common::Version { major: 2, minor: 0 };
        let genus = common::Version { major: 2, minor: 0 };

        // KERI v2.0, genus v2.0, JSON, size 384
        let vs =
            common::versify_v2(Some("KERI"), Some(&version), Some(&genus), Some("JSON"), Some(384))
                .unwrap();

        // Format: PPPPMmmGggKKKKBBBB.
        // KERI + CAA + CAA + JSON + size(384) + .
        assert_eq!(vs.len(), 19);
        assert!(vs.ends_with('.'));
        assert!(vs.starts_with("KERI"));

        // Deversify roundtrip
        let result = common::deversify_v2(&vs).unwrap();
        assert_eq!(result.ident, "KERI");
        assert_eq!(result.kind, "JSON");
        assert_eq!(result.version.major, 2);
        assert_eq!(result.version.minor, 0);
        assert_eq!(result.genus.major, 2);
        assert_eq!(result.genus.minor, 0);
        assert_eq!(result.size, 384);
    }

    #[test]
    fn versify_v2_defaults() {
        // Test with defaults
        let vs = common::versify_v2(None, None, None, None, None).unwrap();
        assert_eq!(vs.len(), 19);
        assert!(vs.ends_with('.'));

        let result = common::deversify_v2(&vs).unwrap();
        assert_eq!(result.ident, "KERI");
        assert_eq!(result.kind, "JSON");
        assert_eq!(result.version.major, 2);
        assert_eq!(result.version.minor, 0);
        assert_eq!(result.size, 0);
    }

    #[test]
    fn versify_v2_unhappy_paths() {
        // Invalid ident
        assert!(common::versify_v2(Some("CESR"), None, None, None, None).is_err());
        // Invalid kind
        assert!(common::versify_v2(None, None, None, Some("CESR"), None).is_err());
    }

    #[test]
    fn deversify_v2_unhappy_paths() {
        // Invalid format (v1 format)
        assert!(common::deversify_v2("KERI10JSON000000_").is_err());
        // Too short
        assert!(common::deversify_v2("KERICAA").is_err());
        // Invalid ident
        assert!(common::deversify_v2("CESRCAACAAJSONAAAA.").is_err());
    }

    #[test]
    fn sniff_v2_test() {
        let version = common::Version { major: 2, minor: 0 };
        let genus = common::Version { major: 2, minor: 0 };

        // Create a JSON message with v2 version string
        let vs =
            common::versify_v2(Some("KERI"), Some(&version), Some(&genus), Some("JSON"), Some(0))
                .unwrap();

        // Build a minimal JSON with version string as first field
        let json = format!("{{\"v\":\"{vs}\",\"t\":\"icp\"}}");
        let json_with_size = {
            let size = json.len() as u32;
            let vs_sized = common::versify_v2(
                Some("KERI"),
                Some(&version),
                Some(&genus),
                Some("JSON"),
                Some(size + 10), // Account for size change
            )
            .unwrap();
            format!("{{\"v\":\"{vs_sized}\",\"t\":\"icp\"}}")
        };

        // Sniff should find the v2 version string
        let result = common::sniff_v2(json_with_size.as_bytes()).unwrap();
        assert_eq!(result.ident, "KERI");
        assert_eq!(result.kind, "JSON");
        assert_eq!(result.version.major, 2);
        assert_eq!(result.version.minor, 0);
    }

    #[test]
    fn sniff_any_test() {
        // Test v1 detection
        let v1_json = dat!({"v":"KERI10JSON000030_","t":"icp"}).to_json().unwrap();
        let result = common::sniff_any(v1_json.as_bytes()).unwrap();
        match result {
            common::SniffResultAny::V1(r) => {
                assert_eq!(r.ident, "KERI");
                assert_eq!(r.version.major, 1);
                assert_eq!(r.version.minor, 0);
            }
            common::SniffResultAny::V2(_) => panic!("expected v1 result"),
        }

        // Test v2 detection
        let version = common::Version { major: 2, minor: 0 };
        let genus = common::Version { major: 2, minor: 0 };
        let vs =
            common::versify_v2(Some("KERI"), Some(&version), Some(&genus), Some("JSON"), Some(100))
                .unwrap();
        let v2_json = format!("{{\"v\":\"{vs}\",\"t\":\"icp\"}}");

        let result = common::sniff_any(v2_json.as_bytes()).unwrap();
        match result {
            common::SniffResultAny::V2(r) => {
                assert_eq!(r.ident, "KERI");
                assert_eq!(r.version.major, 2);
                assert_eq!(r.version.minor, 0);
            }
            common::SniffResultAny::V1(_) => panic!("expected v2 result"),
        }
    }
}
