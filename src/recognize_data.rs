#[macro_export]
macro_rules! recognize_data (
  ($i:expr, $submac:ident!( $($args:tt)* )) => (
    {
      use $crate::lib::std::result::Result::*;

      use $crate::Offset;
      use $crate::Slice;
      let i_ = $i.clone();
      match $submac!(i_, $($args)*) {
        Ok((i, o)) => {
          let index = (&$i).offset(&i);
          Ok((i, (($i).slice(..index), o)))
        },
        Err(e)    => Err(e)
      }
    }
  );
  ($i:expr, $f:expr) => (
    recognize_data!($i, call!($f))
  );
);
