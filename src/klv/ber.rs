use errors;
use nom::IResult;

pub fn ber(i: &[u8]) -> IResult<&[u8], u32> {
    let (remain, start) = map!(i, take!(1), |s| s[0])?;
    let value = start & 0x7F;
    // Short form
    if start & 0x80 == 0 {
        Ok((remain, value as u32))
    // Long form
    } else {
        // Specifically reject the case as an error where 0 bytes are used to represent the long form.
        // ST0601.12 does not provide guidance in the case where the subsequent byte is 0.
        if value == 0 {
            return Err(errors::nom_fail(i, 0x4f9206f6));
        }
        map_res!(remain, take!(value), |bytes: &[u8]| {
            bytes.iter()
            .try_fold(0u32, |acc, &b| acc.checked_mul(1 << 8)
            .map(|acc| acc | b as u32))
            // If the value was unable to fit in a u32, return an error.
            .ok_or(errors::nom_fail(i, 0x63987942))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::ber;
    use nom::{self, Needed};

    #[test]
    fn incomplete() {
        let len_empty = &[];
        assert_eq!(ber(len_empty), Err(nom::Err::Incomplete(Needed::Size(1))));
    }

    #[test]
    fn short_form() {
        let len76 = &[0b0100_1100];
        assert_eq!(ber(len76), Ok((&[] as &[_], 76)));
    }

    #[test]
    fn long_form() {
        let len201 = &[0b1000_0001, 0b1100_1001];
        assert_eq!(ber(len201), Ok((&[] as &[_], 201)));
    }
}
