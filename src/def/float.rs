use super::{
	alignment::{Alignable, Alignment},
	layout::{CowDef, Layable, Layout},
	sexp_pair, Def, Endianness,
};
use lexpr::Value;

#[derive(Clone, Copy, Debug)]
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

#[derive(Clone, Copy, Debug)]
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
