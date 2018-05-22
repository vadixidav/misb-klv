use nom::{simple_errors::Context, Err, ErrorKind};

pub(crate) fn nom_fail<I>(i: I, code: u32) -> Err<I> {
    Err::Failure(Context::Code(i, ErrorKind::Custom(code)))
}
