mod ber;
mod ber_oid;
mod tlv;

pub use self::ber::*;
pub use self::ber_oid::*;
pub use self::tlv::*;

/// The UAS Datalink Local Set Universal Key found at the beginning of a MISB 601 packet.
const UDL_UNIVERSAL_KEY: [u8; 16] = [
    0x06, 0x0E, 0x2B, 0x34, 0x02, 0x0B, 0x01, 0x01, 0x0E, 0x01, 0x03, 0x01, 0x01, 0x00, 0x00, 0x00,
];

/// Get the bytes of a UAS Datalink Local Set Packet payload.
named!(
    pub udl_bytes,
    do_parse!(tag!(UDL_UNIVERSAL_KEY) >> length: call!(ber) >> bytes: take!(length) >> (bytes))
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
