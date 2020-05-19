use super::{
	alignment::{Alignable, Alignment},
	layout::{CowDef, Layable, Layout},
	parse::{self, Parse, ParseError},
	sexp_pair, Def,
};
use lexpr::Value;
use std::num::NonZeroU64;

#[derive(Clone, Debug, Hash)]
pub struct Array {
	pub name: Option<String>,

	// when None, means an array of undefined length
	pub length: Option<NonZeroU64>,

	pub stride: Option<NonZeroU64>,
	pub def: Box<Def>,
}

impl Array {
	pub fn named(name: impl Into<String>, def: Def, length: Option<NonZeroU64>) -> Self {
		let mut array = Self::anonymous(def, length);
		array.name = Some(name.into());
		array
	}

	pub fn anonymous(def: Def, length: Option<NonZeroU64>) -> Self {
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
		// TODO: consider the effect of none length?
		self.def.align()
	}
}

impl Layable for Array {
	fn layout(&self) -> Layout {
		let mut layout = Layout::default();

		if let Some(length) = self.length {
			let element_size = self.def.layout().size;
			for _ in 0..length.get() {
				layout.append_with_size(CowDef::Borrowed(&self.def), element_size);
			}
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
		let mut def = vec![Self::symbol("array")];

		if let Some(ref length) = native.length {
			def.push(sexp_pair(Self::symbol("length"), length.get()));
		}

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

impl Parse for Array {
	fn from_sexp(sexp: &Value) -> Result<Self, ParseError> {
		let name = parse::str_field(&sexp, "name").map(ToString::to_string);
		let length = parse::nonzero_u64_field(&sexp, "length")?;
		let stride = parse::nonzero_u64_field(&sexp, "stride")?;

		let def = sexp
			.to_ref_vec()
			.and_then(|mut v| v.pop())
			.ok_or(ParseError::EmptyList)
			.and_then(Def::from_sexp)?;

		Ok(Self {
			name,
			length,
			stride,
			def: Box::new(def),
		})
	}
}
