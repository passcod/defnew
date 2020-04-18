use super::{
	alignment::{Alignable, Alignment},
	layout::{CowDef, Layable, Layout},
	sexp_pair, Def,
};
use lexpr::Value;
use std::num::NonZeroU64;

#[derive(Clone, Debug)]
pub struct Array {
	pub name: Option<String>,
	pub length: NonZeroU64,
	pub stride: Option<NonZeroU64>,
	pub def: Box<Def>,
}

impl Array {
	pub fn named(name: impl Into<String>, def: Def, length: NonZeroU64) -> Self {
		let mut array = Self::anonymous(def, length);
		array.name = Some(name.into());
		array
	}

	pub fn anonymous(def: Def, length: NonZeroU64) -> Self {
		Self {
			name: None,
			length,
			stride: None,
			def: Box::new(def),
		}
	}
}

impl Alignable for Array {
	fn align(&self) -> Alignment {
		// TODO: consider the effect of a custom stride?
		self.def.align()
	}
}

impl Layable for Array {
	fn layout(&self) -> Layout {
		let mut layout = Layout::default();

		let element_size = self.def.layout().size;
		for _ in 0..self.length.get() {
			layout.append_with_size(CowDef::Borrowed(&self.def), element_size);
		}

		layout
	}
}

impl From<Array> for Def {
	fn from(inner: Array) -> Self {
		Self::Array(inner)
	}
}

impl From<Array> for Value {
	fn from(native: Array) -> Self {
		let mut def = vec![
			Self::symbol("array"),
			sexp_pair(Self::symbol("length"), native.length.get()),
		];

		if let Some(ref name) = native.name {
			def.push(sexp_pair(Self::symbol("name"), name.as_str()));
		}

		if let Some(stride) = native.stride {
			def.push(sexp_pair(Self::symbol("stride"), stride.get()));
		}

		def.push((*native.def).into());

		Self::list(def)
	}
}
