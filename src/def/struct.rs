use super::{
	alignment::{Alignable, Alignment},
	layout::{CowDef, Layable, Layout},
	parse::{self, Parse, ParseError},
	sexp_pair, Def,
};
use lexpr::Value;
use log::trace;

#[derive(Clone, Debug, Hash)]
pub struct Field {
	pub name: Option<String>,
	pub def: Def,
}

impl Field {
	pub fn named(name: impl Into<String>, def: impl Into<Def>) -> Self {
		Self {
			name: Some(name.into()),
			def: def.into(),
		}
	}

	pub fn anonymous(def: impl Into<Def>) -> Self {
		Self {
			name: None,
			def: def.into(),
		}
	}
}

impl From<Field> for Value {
	fn from(native: Field) -> Self {
		let mut fd = vec![Self::symbol("field")];

		if let Some(name) = native.name {
			fd.push(name.into());
		}

		fd.push(native.def.into());

		Self::list(fd)
	}
}

#[derive(Clone, Debug, Hash)]
pub struct Struct {
	pub name: Option<String>,
	pub packed: Option<Alignment>,
	pub align: Option<Alignment>,
	pub fields: Vec<Field>,
}

// TODO: check that field names are unique on create

impl Alignable for Struct {
	fn align(&self) -> Alignment {
		let mut align = Alignment::default();

		for field in &self.fields {
			let field_align = if let Some(pack_align) = self.packed {
				pack_align.min(field.def.align())
			} else {
				field.def.align()
			};

			align.increase_to(field_align);
		}

		if let Some(min_align) = self.align {
			align.increase_to(min_align);
		}

		align
	}
}

impl Layable for Struct {
	fn layout(&self) -> Layout {
		let align = self.align();

		// Start with a current offset of 0 bytes.
		let mut layout = Layout::default();

		// For each field in declaration order in the struct,
		for field in &self.fields {
			// first determine the size and alignment of the field.
			trace!("get field layout");
			let field_size = field.def.layout().size;
			let field_align = field.def.align();

			let effective_align = if self.packed.is_some() {
				field_align.min(align)
			} else {
				field_align
			};

			// If the current offset is not a multiple of the field's alignment, then add padding
			// bytes to the current offset until it is a multiple of the field's alignment.
			if layout.size > 0 {
				trace!("field  pad {:2} % {:2}", layout.size / 8, effective_align,);
				layout.pad_to_align(effective_align);
			}

			// The offset for the field is what the current offset is now.
			// Then increase the current offset by the size of the field.
			trace!("field: {:?}", field);
			layout.append_with_size_and_name(
				field.name.clone(),
				CowDef::Borrowed(&field.def),
				field_size,
			);
		}

		// Finally, the size of the struct is the current offset rounded up
		// to the nearest multiple of the struct's alignment.
		trace!("struct pad {:2}", align);
		layout.pad_to_align(align);

		layout
	}
}

impl From<Struct> for Value {
	fn from(native: Struct) -> Self {
		let mut def = vec![
			Self::symbol("struct"),
			sexp_pair(Self::symbol("size"), native.layout().size / 8),
		];

		if let Some(ref name) = native.name {
			def.push(sexp_pair(Self::symbol("name"), name.as_str()));
		}

		if let Some(packed) = native.packed {
			def.push(sexp_pair(Self::symbol("packed"), packed));
		}

		def.push(sexp_pair(Self::symbol("align"), native.align()));

		for field in native.fields {
			def.push(field.into());
		}

		Self::list(def)
	}
}

impl Parse for Struct {
	fn from_sexp(sexp: &Value) -> Result<Self, ParseError> {
		let name = parse::str_field(&sexp, "name").map(ToString::to_string);
		let packed = parse::alignment_field(&sexp, "packed")?;
		let align = parse::alignment_field(&sexp, "align")?;

		let mut fields = Vec::new();
		for field in sexp.to_ref_vec().unwrap_or_default() {
			let (kind, name, def) = match (field.get(0), field.get(1), field.get(2)) {
				(Some(Value::Symbol(kind)), Some(Value::String(name)), Some(def)) => {
					(kind, Some(name), def)
				}
				(Some(Value::Symbol(kind)), Some(def), None) => (kind, None, def),
				_ => continue,
			};

			if kind.as_ref() != "field" {
				continue;
			}

			fields.push(if let Some(name) = name {
				Field::named(name.as_ref(), Def::from_sexp(def)?)
			} else {
				Field::anonymous(Def::from_sexp(def)?)
			});
		}

		Ok(Self {
			name,
			packed,
			align,
			fields,
		})
	}
}
