use super::{
	alignment::{Alignable, Alignment},
	castable::{CastError, Castable},
	div_round_up,
	fillable::{FillError, Fillable},
	layout::{CowDef, Layable, Layout},
	parse::{self, Parse, ParseError},
	sexp_pair, ByteWidth, Def, Endianness, Integral,
};
use lexpr::Value;
use std::convert::{TryFrom, TryInto};

#[derive(Clone, Debug, Hash)]
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

#[derive(Clone, Debug, Hash)]
pub struct Enum {
	pub name: Option<String>,
	pub width: Option<ByteWidth>,
	pub endian: Endianness,
	pub variants: Vec<Variant>,
}

// TODO: check that variant names are unique on create

impl Enum {
	fn true_width(&self) -> u64 {
		let max_value = self.variants.iter().map(|v| v.value).max().unwrap_or(0);
		let variant_count = u64::try_from(self.variants.len()).unwrap();

		let fit_width = div_round_up(max_value.max(variant_count), 256);
		let hint_width = u64::from(self.width.map(|n| n.get()).unwrap_or(0));

		fit_width.max(hint_width)
	}

	fn to_integral(&self) -> Option<Integral> {
		ByteWidth::new(
			self.true_width()
				.try_into()
				.unwrap_or_else(|_| todo!("enums larger than 256 bits")),
		)
		.map(|width| Integral {
			signed: false,
			endian: self.endian,
			width,
		})
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

impl Fillable for Enum {
	fn fill_from_str(&self, s: &str) -> Result<Vec<u8>, FillError> {
		let value = self
			.variants
			.iter()
			.find_map(|variant| {
				if &variant.name == s {
					Some(variant.value)
				} else {
					None
				}
			})
			.ok_or(FillError::UnknownVariant)?;

		if let Some(int) = self.to_integral() {
			int.fill_from_str(&value.to_string())
		} else {
			Ok(Vec::new())
		}
	}
}

impl Castable for Enum {
	fn cast_to_string(&self, raw: &[u8]) -> Result<String, CastError> {
		if let Some(int) = self.to_integral() {
			let value: u64 = int
				.cast_to_string(raw)?
				.parse()
				.or(Err(CastError::EnumValueTooLarge))?;

			let variant = self
				.variants
				.iter()
				.find_map(|variant| {
					if variant.value == value {
						Some(variant.name.clone())
					} else {
						None
					}
				})
				.unwrap_or_else(|| value.to_string());

			Ok(variant)
		} else {
			Ok(String::new())
		}
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
