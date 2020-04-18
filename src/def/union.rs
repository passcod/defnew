use super::{
	alignment::{Alignable, Alignment},
	layout::{CowDef, Layable, Layout},
	sexp_pair, Def,
};
use lexpr::Value;

#[derive(Clone, Debug)]
pub struct Altern {
	pub name: String,
	pub def: Def,
}

impl From<Altern> for Value {
	fn from(native: Altern) -> Self {
		Self::list(vec![
			Self::symbol("altern"),
			native.name.into(),
			native.def.into(),
		])
	}
}

#[derive(Clone, Debug)]
pub struct Union {
	pub name: Option<String>,
	pub align: Option<Alignment>,
	pub alterns: Vec<Altern>,
}

impl Alignable for Union {
	fn align(&self) -> Alignment {
		let max_align_of_variants = self
			.alterns
			.iter()
			.map(|a| a.def.align())
			.max()
			.unwrap_or_default();

		if let Some(custom_align) = self.align {
			max_align_of_variants.max(custom_align)
		} else {
			max_align_of_variants
		}
	}
}

impl Layable for Union {
	fn layout(&self) -> Layout {
		let max_size_of_variants = self
			.alterns
			.iter()
			.map(|a| a.def.layout().size)
			.max()
			.unwrap_or_default();

		let mut layout = Layout::default();
		layout.append_with_size(CowDef::Owned(self.clone().into()), max_size_of_variants * 8);
		layout
	}
}

impl From<Union> for Def {
	fn from(inner: Union) -> Self {
		Self::Union(inner)
	}
}

impl From<Union> for Value {
	fn from(native: Union) -> Self {
		let mut def = vec![Self::symbol("union")];

		if let Some(ref name) = native.name {
			def.push(sexp_pair(Self::symbol("name"), name.as_str()));
		}

		if let Some(align) = native.align {
			def.push(sexp_pair(Self::symbol("align"), align));
		}

		for altern in native.alterns {
			def.push(altern.into());
		}

		Self::list(def)
	}
}
