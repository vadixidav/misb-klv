use errors;
use nom::IResult;

fn length(i: &[u8]) -> IResult<&[u8], u32> {
    take_till!(i, |b| b & 0x80 == 0).and_then(|(remain, higher)| {
        higher
            .iter()
            .chain(Some(&remain[0]))
            .try_fold(0u32, |acc, &b| acc.checked_mul(1 << 7).map(|acc| acc | (b & 0x7F) as u32))
            .map(|len| (&remain[1..], len))
            // If the KLV length was unable to fit in a u32, return an error.
            .ok_or(errors::nom_fail(i, 0x7fd10001))
    })
}

#[cfg(test)]
mod tests {
    use super::length;
    use nom::{self, simple_errors::Context, ErrorKind, Needed};

    #[test]
    fn length_0_incomplete() {
        let tag_empty = &[];
        assert_eq!(
            length(tag_empty),
            Err(nom::Err::Incomplete(Needed::Size(1)))
        );
    }

    #[test]
    fn length_1_incomplete() {
        let tag98 = &[0b11100010];
        assert_eq!(length(tag98), Err(nom::Err::Incomplete(Needed::Size(1))));
    }

    #[test]
    fn length_1() {
        let tag98 = &[0b01100010];
        assert_eq!(length(tag98), Ok((&[] as &[_], 98)));
    }

    #[test]
    fn length_2() {
        let tag144 = &[0b10000001, 0b00010000];
        assert_eq!(length(tag144), Ok((&[] as &[_], 144)));
    }

    #[test]
    fn length_3() {
        let tag23298 = &[0b1000_0001, 0b1011_0110, 0b0000_0010];
        assert_eq!(length(tag23298), Ok((&[] as &[_], 23298)));
    }

    #[test]
    fn length_overflow() {
        let overflow = &[
            0b1100_0001,
            0b1011_0110,
            0b1000_0010,
            0b1000_0000,
            0b1000_0000,
            0b0000_0000,
        ];
        assert_eq!(
            length(overflow),
            Err(nom::Err::Failure(Context::Code(
                overflow as &[_],
                ErrorKind::Custom(0x7fd10001)
            )))
        );
    }
}
