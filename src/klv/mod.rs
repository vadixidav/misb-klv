mod ber;
mod ber_oid;

const UAS_DATALINK_LOCAL_SET_UNIVERSAL_KEY: [u8; 16] = [
    0x06, 0x0E, 0x2B, 0x34, 0x02, 0x0B, 0x01, 0x01, 0x0E, 0x01, 0x03, 0x01, 0x01, 0x00, 0x00, 0x00,
];

named!(
    uas_datalink_ls_packet,
    do_parse!(
        tag!(UAS_DATALINK_LOCAL_SET_UNIVERSAL_KEY) >> length: call!(ber::length)
            >> bytes: take!(length) >> (bytes)
    )
);

#[cfg(test)]
mod tests {
    use super::uas_datalink_ls_packet;

    #[test]
    fn test_uas_datalink_ls_packet_extraction() {
        let bytes = [
            0x06, 0x0E, 0x2B, 0x34, 0x02, 0x0B, 0x01, 0x01, 0x0E, 0x01, 0x03, 0x01, 0x01, 0x00,
            0x00, 0x00, 0x04, 0x01, 0x02, 0x03, 0x04,
        ];

        assert_eq!(
            uas_datalink_ls_packet(&bytes[..]),
            Ok((&[] as &[_], &[0x01, 0x02, 0x03, 0x04][..]))
        );
    }
}
