use nom::{Err, ErrorKind};

#[cfg(not(feature = "verbose-errors"))]
use nom::simple_errors::Context;
#[cfg(feature = "verbose-errors")]
use nom::verbose_errors::Context;

pub(crate) fn nom_fail<I>(i: I, code: u32) -> Err<I> {
    Err::Failure(Context::Code(i, ErrorKind::Custom(code)))
}
