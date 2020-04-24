use super::{
	alignment::{Alignable, Alignment},
	castable::{CastError, Castable},
	fillable::{FillError, Fillable},
	layout::{CowDef, Layable, Layout},
	parse::{self, Parse, ParseError},
	sexp_pair, Def,
};
use lexpr::Value;
use std::convert::TryFrom;

#[derive(Clone, Debug, Hash)]
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

#[derive(Clone, Debug, Hash)]
pub struct Union {
	pub name: Option<String>,
	pub align: Option<Alignment>,
	pub alterns: Vec<Altern>,
}

impl Union {
	pub fn max_size_of_variants(&self) -> u64 {
		self.alterns
			.iter()
			.map(|a| a.def.layout().size)
			.max()
			.unwrap_or_default()
	}
}

// TODO: check that altern names are unique on create

impl Alignable for Union {
	fn align(&self) -> Alignment {
		let mut max_align_of_variants = self
			.alterns
			.iter()
			.map(|a| a.def.align())
			.max()
			.unwrap_or_default();

		if let Some(custom_align) = self.align {
			max_align_of_variants.increase_to(custom_align);
		}

		max_align_of_variants
	}
}

impl Layable for Union {
	fn layout(&self) -> Layout {
		let mut layout = Layout::default();
		layout.append_with_size(
			CowDef::Owned(self.clone().into()),
			self.max_size_of_variants() * 8,
		);
		layout.pad_to_align(self.align());
		layout
	}
}

impl Fillable for Union {
	fn fill_from_str(&self, s: &str) -> Result<Vec<u8>, FillError> {
		let def = self
			.alterns
			.iter()
			.find_map(|altern| {
				if &altern.name == s {
					Some(&altern.def)
				} else {
					None
				}
			})
			.ok_or(FillError::UnknownAltern)?;

		let mut bytes = def.layout().fill(vec![s.to_string()], Default::default())?;

		// pad to union size
		let max_size = usize::try_from(self.max_size_of_variants())
			.expect("size of union does not fit in usize");
		if max_size % 8 == 0 {
			bytes.extend(vec![0; max_size / 8 - bytes.len()]);
		} else {
			todo!("fill for unions with non-aligned alterns");
		}

		Ok(bytes)
	}
}

impl Castable for Union {
	fn cast_to_string(&self, _raw: &[u8]) -> Result<String, CastError> {
		todo!("casting unions")
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

impl Parse for Union {
	fn from_sexp(sexp: &Value) -> Result<Self, ParseError> {
		let name = parse::str_field(&sexp, "name").map(ToString::to_string);
		let align = parse::alignment_field(&sexp, "align")?;

		let mut alterns = Vec::new();
		for field in sexp.to_ref_vec().unwrap_or_default() {
			let (kind, name, def) = match (field.get(0), field.get(1), field.get(2)) {
				(Some(Value::Symbol(kind)), Some(Value::String(name)), Some(def)) => {
					(kind, name, def)
				}
				_ => continue,
			};

			if kind.as_ref() != "altern" {
				continue;
			}

			alterns.push(Altern {
				name: name.to_string(),
				def: Def::from_sexp(def)?,
			});
		}

		Ok(Self {
			name,
			align,
			alterns,
		})
	}
}
