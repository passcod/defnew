use super::{
	alignment::{Alignable, Alignment},
	castable::{CastError, Castable},
	fillable::{FillError, Fillable},
	layout::{CowDef, Layable, Layout},
	parse::{self, Parse, ParseError},
	sexp_pair, Def, Endianness,
};
use lexpr::Value;
use std::str::FromStr;
use thiserror::Error;

#[derive(Clone, Copy, Debug, Hash)]
pub enum Format {
	Binary16,
	Binary32,
	Binary64,
	Binary128,
	Binary256,
	Decimal32,
	Decimal64,
	Decimal128,
}

impl From<Format> for Value {
	fn from(native: Format) -> Self {
		Self::symbol(match native {
			Format::Binary16 => "binary-16",
			Format::Binary32 => "binary-32",
			Format::Binary64 => "binary-64",
			Format::Binary128 => "binary-128",
			Format::Binary256 => "binary-256",
			Format::Decimal32 => "decimal-32",
			Format::Decimal64 => "decimal-64",
			Format::Decimal128 => "decimal-128",
		})
	}
}

impl FromStr for Format {
	type Err = InvalidFloatFormatError;

	fn from_str(s: &str) -> Result<Self, Self::Err> {
		Ok(match s {
			"binary-16" => Format::Binary16,
			"binary-32" => Format::Binary32,
			"binary-64" => Format::Binary64,
			"binary-128" => Format::Binary128,
			"binary-256" => Format::Binary256,
			"decimal-32" => Format::Decimal32,
			"decimal-64" => Format::Decimal64,
			"decimal-128" => Format::Decimal128,
			format => return Err(InvalidFloatFormatError(format.into())),
		})
	}
}

#[derive(Debug, Error)]
#[error("invalid float format specifier: {0} (expected one of: binary{{16,32,64,128,256}}, decimal{{32,64,128}})")]
pub struct InvalidFloatFormatError(String);

#[derive(Clone, Copy, Debug, Hash)]
pub struct Float {
	pub format: Format,
	pub endian: Endianness,
	pub align: Option<Alignment>,
}

impl Float {
	pub fn width(self) -> u64 {
		match self.format {
			Format::Binary16 => 2_u64,
			Format::Binary32 | Format::Decimal32 => 4_u64,
			Format::Binary64 | Format::Decimal64 => 8_u64,
			Format::Binary128 | Format::Decimal128 => 16_u64,
			Format::Binary256 => 32_u64,
		}
	}
}

impl Alignable for Float {
	fn align(&self) -> Alignment {
		self.align
			.unwrap_or_else(|| Alignment::from_size(self.width()).unwrap())
	}
}

impl Layable for Float {
	fn layout(&self) -> Layout {
		let size = u64::from(self.width());
		let mut layout = Layout::default();
		layout.append_with_size(CowDef::Owned(self.clone().into()), size * 8);
		layout
	}
}

impl Fillable for Float {
	fn fill_from_str(&self, s: &str) -> Result<Vec<u8>, FillError> {
		macro_rules! filler {
			($endian:expr, $numtype:ty, $s:expr) => {{
				let num = <$numtype>::from_str($s)?;
				match $endian {
					Endianness::Big => num.to_be_bytes().to_vec(),
					Endianness::Little => num.to_le_bytes().to_vec(),
					Endianness::Native => num.to_ne_bytes().to_vec(),
					}
				}};
		}

		Ok(match self.format {
			Format::Binary32 => filler!(self.endian, f32, s),
			Format::Binary64 => filler!(self.endian, f64, s),
			_ => todo!("fill for binary{{16,128,256}} and decimal floats"),
		})
	}
}

impl Castable for Float {
	fn cast_to_string(&self, raw: &[u8]) -> Result<String, CastError> {
		macro_rules! caster {
			($endian:expr, $numtype:ty, $r:expr) => {{
				use ::std::{convert::TryInto, mem::size_of};
				let bytes: [u8; size_of::<$numtype>()] = $r.try_into()?;
				match $endian {
					Endianness::Big => <$numtype>::from_be_bytes(bytes).to_string(),
					Endianness::Little => <$numtype>::from_le_bytes(bytes).to_string(),
					Endianness::Native => <$numtype>::from_ne_bytes(bytes).to_string(),
					}
				}};
		}

		Ok(match self.format {
			Format::Binary32 => caster!(self.endian, f32, raw),
			Format::Binary64 => caster!(self.endian, f64, raw),
			_ => todo!("cast for binary{{16,128,256}} and decimal floats"),
		})
	}
}

impl From<Float> for Def {
	fn from(inner: Float) -> Self {
		Self::Float(inner)
	}
}

impl From<Float> for Value {
	fn from(native: Float) -> Self {
		let mut def = vec![
			Self::symbol("float"),
			sexp_pair(Self::symbol("format"), native.format),
			sexp_pair(Self::symbol("endian"), native.endian),
		];

		if let Some(align) = native.align {
			def.push(sexp_pair(Self::symbol("align"), align));
		}

		Self::list(def)
	}
}

impl Parse for Float {
	fn from_sexp(sexp: &Value) -> Result<Self, ParseError> {
		let endian = parse::endianness_field(&sexp, "endian")?.unwrap_or_default();
		let align = parse::alignment_field(&sexp, "align")?;
		let format = parse::required("format", parse::sym_field(&sexp, "format"))?.parse()?;

		Ok(Self {
			format,
			endian,
			align,
		})
	}
}
