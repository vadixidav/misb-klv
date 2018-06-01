use chrono::{DateTime, NaiveDateTime, Utc};
use errors;
use klv::{ber, ber_oid, udl_bytes};
use nom::{self, be_u16, be_u64, IResult};
use std::iter::FromIterator;
use Boolinator;

#[derive(Clone, Debug)]
pub struct TLVRaw<'a> {
    pub tag: u32,
    pub bytes: &'a [u8],
}

/// Written according to [MISB 601.12](http://www.gwg.nga.mil/misb/docs/standards/ST0601.12.pdf).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum TLV {
    /// TAG 1
    Checksum(u16),
    /// TAG 2
    PrecisionTimeStamp(DateTime<Utc>),
    /// TAG 3
    MissionID(String),
    /// TAG 4
    PlatformTailNumber(String),
    Unknown(Vec<u8>),
}

/// Parse a TLV from a UAS Datalink Local Set Packet.
named!(
    pub raw_tlv<TLVRaw>,
    do_parse!(tag: call!(ber_oid) >> length: call!(ber) >> bytes: take!(length) >> (TLVRaw{tag, bytes}))
);

/// Extract all the TLVs from an entire UAS Datalink Local Set Packet.
pub fn udl_tlvs<'a>(i: &'a [u8]) -> IResult<&[u8], Vec<TLVRaw<'a>>> {
    map_res!(i, udl_bytes, |i: &'a [u8]| many0!(i, complete!(raw_tlv))
        .map(|t| t.1))
}

// Try to create a string from an ASCII value.
fn ascii_string<'a>(i: &'a [u8]) -> Result<String, nom::Err<&'a [u8]>> {
    i.iter().all(u8::is_ascii).as_result_from(
        || String::from_iter(i.iter().map(|&b| b as char)),
        || errors::nom_fail(i, 0x3a9f0996),
    )
}

/// Parse all the TLVs in a UAS Datalink Local Set Packet.
pub fn parse_tlvs<'a>(tlvs: Vec<TLVRaw<'a>>) -> Result<Vec<TLV>, nom::Err<&'a [u8]>> {
    tlvs.into_iter()
        .map(|TLVRaw { tag, bytes }| {
            Ok(match tag {
                1 => TLV::Checksum(be_u16(bytes)?.1),
                2 => {
                    let ts = be_u64(bytes)?.1;
                    let seconds = ts / 1_000_000;
                    // Remove the seconds and represent the remainder as nanoseconds.
                    let nanos = (ts - seconds * 1_000_000) * 1000;
                    TLV::PrecisionTimeStamp(DateTime::from_utc(
                        NaiveDateTime::from_timestamp(seconds as i64, nanos as u32),
                        Utc,
                    ))
                }
                3 => TLV::MissionID(ascii_string(bytes)?),
                4 => TLV::PlatformTailNumber(ascii_string(bytes)?),
                _ => TLV::Unknown(bytes.to_vec()),
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_table_11_full_udl_example() {
        // Data taken from `Table 10: Example “Dynamic & Constant” MISMMS Packet Data` in MISB 902.7.
        let bytes = include_bytes!("table_902.7-11_full_UDL_packet.bin");
        let tlvs = udl_tlvs(&bytes[..])
            .and_then(|t| parse_tlvs(t.1))
            .expect("unable to parse out TLVs");

        assert_eq!(
            tlvs[0],
            TLV::PrecisionTimeStamp(DateTime::from_utc(
                NaiveDateTime::from_timestamp(1_231_798_102, 0),
                Utc
            ))
        );
    }
}
