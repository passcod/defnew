use super::{
	alignment::{Alignable, Alignment},
	div_round_up,
	layout::{CowDef, Layable, Layout},
	sexp_pair, ByteWidth, Def, Endianness,
};
use lexpr::Value;
use std::convert::TryFrom;

#[derive(Clone, Debug)]
pub struct Variant {
	pub name: String,
	pub value: u64,
}

impl From<Variant> for Value {
	fn from(native: Variant) -> Self {
		Self::list(vec![
			Self::symbol("variant"),
			native.name.into(),
			native.value.into(),
		])
	}
}

#[derive(Clone, Debug)]
pub struct Enum {
	pub name: Option<String>,
	pub width: Option<ByteWidth>,
	pub endian: Endianness,
	pub variants: Vec<Variant>,
}

impl Enum {
	fn true_width(&self) -> u64 {
		let max_value = self.variants.iter().map(|v| v.value).max().unwrap_or(0);
		let variant_count = u64::try_from(self.variants.len()).unwrap();

		let fit_width = div_round_up(max_value.max(variant_count), 256);
		let hint_width = u64::from(self.width.map(|n| n.get()).unwrap_or(0));

		fit_width.max(hint_width)
	}
}

impl Alignable for Enum {
	fn align(&self) -> Alignment {
		Alignment::from_size(self.true_width()).unwrap()
	}
}

impl Layable for Enum {
	fn layout(&self) -> Layout {
		let mut layout = Layout::default();
		layout.append_with_size(CowDef::Owned(self.clone().into()), self.true_width() * 8);
		layout
	}
}

impl From<Enum> for Def {
	fn from(inner: Enum) -> Self {
		Self::Enum(inner)
	}
}

impl From<Enum> for Value {
	fn from(native: Enum) -> Self {
		let mut def = vec![
			Self::symbol("enum"),
			sexp_pair(Self::symbol("width"), native.true_width()),
			sexp_pair(Self::symbol("endian"), native.endian),
		];

		if let Some(ref name) = native.name {
			def.push(sexp_pair(Self::symbol("name"), name.as_str()));
		}

		for variant in native.variants {
			def.push(variant.into());
		}

		Self::list(def)
	}
}
