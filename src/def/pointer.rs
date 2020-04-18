use super::{
	alignment::{Alignable, Alignment},
	layout::{CowDef, Layable, Layout},
	sexp_pair, ByteWidth, Def, Endianness,
};
use lexpr::Value;
use std::{fmt, str::FromStr};
use thiserror::Error;

#[derive(Clone, Copy, Debug)]
pub enum Context {
	Local,
	Remote,
}

impl From<Context> for Value {
	fn from(native: Context) -> Self {
		Self::string(native.to_string())
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
	type Err = ParseContextError;

	fn from_str(s: &str) -> Result<Self, Self::Err> {
		match s {
			"local" => Ok(Self::Local),
			"remote" => Ok(Self::Remote),
			_ => Err(ParseContextError),
		}
	}
}

#[derive(Debug, Error)]
#[error("pointer context may be local or remote")]
pub struct ParseContextError;

#[derive(Clone, Debug)]
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
