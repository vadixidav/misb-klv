mod ber;
mod ber_oid;

use self::ber::ber;
use self::ber_oid::ber_oid;

use nom::{self, IResult};

/// The UAS Datalink Local Set Universal Key found at the beginning of a MISB 601 packet.
const UDL_UNIVERSAL_KEY: [u8; 16] = [
    0x06, 0x0E, 0x2B, 0x34, 0x02, 0x0B, 0x01, 0x01, 0x0E, 0x01, 0x03, 0x01, 0x01, 0x00, 0x00, 0x00,
];

pub struct TLVRaw<'a> {
    pub tag: u32,
    pub bytes: &'a [u8],
}

pub enum TLV {
    Unknown(Vec<u8>),
}

/// Get the bytes of a UAS Datalink Local Set Packet payload.
named!(
    pub udl_bytes,
    do_parse!(tag!(UDL_UNIVERSAL_KEY) >> length: call!(ber) >> bytes: take!(length) >> (bytes))
);

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

#[cfg(test)]
mod tests {
    use super::udl_bytes;

    #[test]
    fn good_uas_datalink_ls_packet_bytes_extraction() {
        let bytes = [
            0x06, 0x0E, 0x2B, 0x34, 0x02, 0x0B, 0x01, 0x01, 0x0E, 0x01, 0x03, 0x01, 0x01, 0x00,
            0x00, 0x00, 0x04, 0x01, 0x02, 0x03, 0x04,
        ];

        assert_eq!(
            udl_bytes(&bytes[..]),
            Ok((&[] as &[_], &[0x01, 0x02, 0x03, 0x04][..]))
        );
    }
}
