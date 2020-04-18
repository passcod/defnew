use super::{
	alignment::{Alignable, Alignment},
	div_round_up,
	layout::{CowDef, Layable, Layout},
	parse::{self, Parse, ParseError},
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

impl Parse for Enum {
	fn from_sexp(sexp: &Value) -> Result<Self, ParseError> {
		let name = parse::str_field(&sexp, "name").map(ToString::to_string);
		let width = parse::nonzero_u8_field(&sexp, "width")?;
		let endian = parse::endianness_field(&sexp, "endian")?.unwrap_or_default();

		let mut variants = Vec::new();
		let mut value = 0;
		for field in sexp.to_ref_vec().unwrap_or_default() {
			let (kind, name, disc) = match (field.get(0), field.get(1), field.get(2)) {
				(Some(Value::Symbol(kind)), Some(Value::String(name)), Some(disc)) => {
					(kind, name, Some(disc))
				}
				(Some(Value::Symbol(kind)), Some(Value::String(name)), None) => (kind, name, None),
				_ => continue,
			};

			if kind.as_ref() != "variant" {
				continue;
			}

			if let Some(d) = disc {
				value = d.as_u64().ok_or(ParseError::EnumDiscriminantNaN)?;
			}

			variants.push(Variant {
				name: name.to_string(),
				value,
			});

			value += 1;
		}

		Ok(Self {
			name,
			width,
			endian,
			variants,
		})
	}
}
