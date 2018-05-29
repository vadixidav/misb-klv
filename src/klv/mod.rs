mod ber;
mod ber_oid;

use self::ber::ber;
use self::ber_oid::ber_oid;

/// The UAS Datalink Local Set Universal Key found at the beginning of a MISB 601 packet.
const UDL_UNIVERSAL_KEY: [u8; 16] = [
    0x06, 0x0E, 0x2B, 0x34, 0x02, 0x0B, 0x01, 0x01, 0x0E, 0x01, 0x03, 0x01, 0x01, 0x00, 0x00, 0x00,
];

pub struct TLVRaw<'a> {
    pub tag: u32,
    pub bytes: &'a [u8],
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

/// Parse all the TLV from any given byte slice.
named!(
    pub all_raw_tlvs<Vec<TLVRaw>>,
    many0!(raw_tlv)
);

/// Extract all the TLVs from an entire UAS Datalink Local Set Packet.
named!(
    pub udl_tlvs<Vec<TLVRaw>>,
    map_res!(udl_bytes, |i| all_raw_tlvs(i).map(|t| t.1))
);

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
