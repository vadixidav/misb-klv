use chrono::{DateTime, NaiveDateTime, Utc};
use klv::{ber, ber_oid, udl_bytes};
use nom::{self, be_u16, be_u64, IResult};

pub struct TLVRaw<'a> {
    pub tag: u32,
    pub bytes: &'a [u8],
}

/// Written according to [MISB 601.12](http://www.gwg.nga.mil/misb/docs/standards/ST0601.12.pdf).
#[derive(Serialize, Deserialize)]
pub enum TLV {
    Checksum(u16),
    PrecisionTimeStamp(DateTime<Utc>),
    Unknown(Vec<u8>),
}

/// Parse a TLV from a UAS Datalink Local Set Packet.
named!(
    pub raw_tlv<TLVRaw>,
    do_parse!(tag: call!(ber_oid) >> length: call!(ber) >> bytes: take!(length) >> (TLVRaw{tag, bytes}))
);

/// Extract all the TLVs from an entire UAS Datalink Local Set Packet.
pub fn udl_tlvs<'a>(i: &'a [u8]) -> IResult<&[u8], Vec<TLVRaw<'a>>> {
    map_res!(i, udl_bytes, |i: &'a [u8]| many0!(i, raw_tlv).map(|t| t.1))
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
                _ => TLV::Unknown(bytes.to_vec()),
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_table_10_example() {
        // Data taken from `Table 10: Example “Dynamic & Constant” MISMMS Packet Data` in MISB 902.7.
        let bytes = include_bytes!("table10_payload_only.bin");
        let tlvs = many0!(&bytes[..], raw_tlv)
            .and_then(|t| parse_tlvs(t.1))
            .expect("unable to parse out TLVs");
    }
}
