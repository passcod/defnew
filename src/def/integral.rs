use super::{
	alignment::{Alignable, Alignment},
	fillable::{FillError, Fillable},
	layout::{CowDef, Layable, Layout},
	parse::{self, Parse, ParseError},
	sexp_pair, ByteWidth, Def, Endianness,
};
use lexpr::Value;
use std::str::FromStr;

#[derive(Clone, Debug, Hash)]
pub struct Integral {
	pub signed: bool,
	pub endian: Endianness,
	pub width: ByteWidth,
}

impl Alignable for Integral {
	fn align(&self) -> Alignment {
		Alignment::from_size(u64::from(self.width.get()))
			.expect("non-zero u8 did not fit in non-zero u64???")
	}
}

impl Layable for Integral {
	fn layout(&self) -> Layout {
		let size = u64::from(self.width.get());
		let mut layout = Layout::default();
		layout.append_with_size(CowDef::Owned(self.clone().into()), size * 8);
		layout
	}
}

impl Fillable for Integral {
	fn fill_from_str(&self, s: &str) -> Result<Vec<u8>, FillError> {
		macro_rules! filler {
			($this:expr, $utype:ty, $itype:ty, $s:expr) => {
				if $this.signed {
					filler!($this.endian, $itype, $s)
				} else {
					filler!($this.endian, $utype, $s)
					}
			};
			($endian:expr, $numtype:ty, $s:expr) => {{
				let num = <$numtype>::from_str($s)?;
				match $endian {
					Endianness::Big => num.to_be_bytes().to_vec(),
					Endianness::Little => num.to_le_bytes().to_vec(),
					Endianness::Native => num.to_ne_bytes().to_vec(),
					}
				}};
		}

		Ok(match self.width.get() {
			1 => filler!(self, u8, i8, s),
			2 => filler!(self, u16, i16, s),
			4 => filler!(self, u32, i32, s),
			8 => filler!(self, u64, i64, s),
			16 => filler!(self, u128, i128, s),
			_ => todo!("fill for arbitrary-width integrals"),
		})
	}
}

impl From<Integral> for Def {
	fn from(inner: Integral) -> Self {
		Self::Integral(inner)
	}
}

impl From<Integral> for Value {
	fn from(native: Integral) -> Self {
		Self::list(vec![
			Self::symbol("integral"),
			sexp_pair(Self::symbol("signed"), native.signed),
			sexp_pair(Self::symbol("endian"), native.endian),
			sexp_pair(Self::symbol("width"), native.width.get()),
		])
	}
}

impl Parse for Integral {
	fn from_sexp(sexp: &Value) -> Result<Self, ParseError> {
		let signed = parse::required("signed", parse::bool_field(&sexp, "signed"))?;
		let endian = parse::endianness_field(&sexp, "endian")?.unwrap_or_default();
		let width = parse::required("width", parse::nonzero_u8_field(&sexp, "width")?)?;

		Ok(Self {
			signed,
			endian,
			width,
		})
	}
}
