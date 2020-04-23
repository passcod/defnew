use super::{
	alignment::{Alignable, Alignment},
	fillable::{FillError, Fillable},
	layout::{CowDef, Layable, Layout},
	parse::{self, Parse, ParseError},
	sexp_pair, ByteWidth, Def, Endianness, Integral,
};
use lexpr::Value;
use std::{fmt, str::FromStr};
use thiserror::Error;

#[derive(Clone, Copy, Debug, Hash)]
pub enum Context {
	Local,
	Remote,
}

impl From<Context> for Value {
	fn from(native: Context) -> Self {
		Self::symbol(native.to_string())
	}
}

impl Default for Context {
	fn default() -> Self {
		Self::Local
	}
}

impl fmt::Display for Context {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(
			f,
			"{}",
			match self {
				Context::Local => "local",
				Context::Remote => "remote",
			}
		)
	}
}

impl FromStr for Context {
	type Err = InvalidContextError;

	fn from_str(s: &str) -> Result<Self, Self::Err> {
		match s {
			"local" => Ok(Self::Local),
			"remote" => Ok(Self::Remote),
			_ => Err(InvalidContextError),
		}
	}
}

#[derive(Debug, Error)]
#[error("pointer context may be local or remote")]
pub struct InvalidContextError;

#[derive(Clone, Copy, Debug, Hash)]
pub struct Pointer {
	pub endian: Endianness,
	pub width: ByteWidth,
	pub context: Context,
	pub value: u64,
}

impl Alignable for Pointer {
	fn align(&self) -> Alignment {
		Alignment::from_size(u64::from(self.width.get()))
			.expect("non-zero u8 did not fit in non-zero u64???")
	}
}

impl Layable for Pointer {
	fn layout(&self) -> Layout {
		let size = u64::from(self.width.get());
		let mut layout = Layout::default();
		layout.append_with_size(CowDef::Owned(self.clone().into()), size * 8);
		layout
	}
}

impl Fillable for Pointer {
	fn fill_from_str(&self, s: &str) -> Result<Vec<u8>, FillError> {
		Integral {
			signed: false,
			endian: self.endian,
			width: self.width,
		}
		.fill_from_str(s)
	}
}

impl From<Pointer> for Def {
	fn from(inner: Pointer) -> Self {
		Self::Pointer(inner)
	}
}

impl From<Pointer> for Value {
	fn from(native: Pointer) -> Self {
		Self::list(vec![
			Self::symbol("pointer"),
			sexp_pair(Self::symbol("endian"), native.endian),
			sexp_pair(Self::symbol("width"), native.width.get()),
			sexp_pair(Self::symbol("context"), native.context),
			Self::Number(native.value.into()),
		])
	}
}

impl Parse for Pointer {
	fn from_sexp(sexp: &Value) -> Result<Self, ParseError> {
		let endian = parse::endianness_field(&sexp, "endian")?.unwrap_or_default();
		let width = parse::required("width", parse::nonzero_u8_field(&sexp, "width")?)?;
		let context = parse::required("context", parse::sym_field(&sexp, "context"))?.parse()?;

		let value = sexp
			.to_ref_vec()
			.and_then(|mut v| v.pop())
			.ok_or(ParseError::EmptyList)
			.and_then(|v| {
				v.as_u64()
					.ok_or_else(|| ParseError::MissingField("<pointer value>".into()))
			})?;

		Ok(Self {
			endian,
			width,
			context,
			value,
		})
	}
}
