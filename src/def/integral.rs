use super::{
	alignment::{Alignable, Alignment},
	layout::{CowDef, Layable, Layout},
	parse::{self, Parse, ParseError},
	sexp_pair, ByteWidth, Def, Endianness,
};
use lexpr::Value;

#[derive(Clone, Debug)]
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
