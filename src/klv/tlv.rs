use klv::{ber, ber_oid, udl_bytes};
use nom::{self, IResult};

pub struct TLVRaw<'a> {
    pub tag: u32,
    pub bytes: &'a [u8],
}

pub enum TLV {
    Unknown(Vec<u8>),
}

/// Parse a TLV from a UAS Datalink Local Set Packet.
named!(
    pub raw_tlv<TLVRaw>,
    do_parse!(tag: call!(ber_oid) >> length: call!(ber) >> bytes: take!(length) >> (TLVRaw{tag: tag, bytes: bytes}))
);

/// Extract all the TLVs from an entire UAS Datalink Local Set Packet.
pub fn udl_tlvs<'a>(i: &'a [u8]) -> IResult<&[u8], Vec<TLVRaw<'a>>> {
    map_res!(i, udl_bytes, |i: &'a [u8]| many0!(i, raw_tlv).map(|t| t.1))
}

/// Parse all the TLVs in a UAS Datalink Local Set Packet.
pub fn parse_tlvs<'a>(tlvs: Vec<TLVRaw<'a>>) -> Result<Vec<TLV>, nom::Err<&'a [u8]>> {
    Ok(tlvs
        .into_iter()
        .map(|tlv| match tlv.tag {
            _ => TLV::Unknown(tlv.bytes.to_vec()),
        })
        .collect())
}
