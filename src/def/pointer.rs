use super::{
	alignment::{Alignable, Alignment},
	castable::{CastError, Castable},
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
	/// Local to the bunch of data we're looking at, or local to the def this pointer is in.
	///
	/// This is a fuzzy definition but generally means that the pointer is relative to whatever
	/// the start of the data we were given is.
	///
	/// This is relevant because defs aim to *model* program memory, but are *not* program memory.
	/// A pointer in a def with a context of local is pointing to some other place within that same
	/// def.
	///
	/// Also read the docs for Remote.
	Local,

	/// Remote to this particular data blob or def.
	///
	/// This might mean that it is somewhere in program memory, whether that's inside or outside
	/// the def. But there is no prescribed meaning besides that it is not Local.
	///
	/// All external data that contains pointers starts with Remote pointers, and when applicable
	/// the defnew tooling might convert some Remote pointers to Local pointers, such that they
	/// make sense when read outside of the program context, and tooling may also convert Local
	/// pointers to Remote pointers when using provided data in a program context.
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

#[derive(Clone, Debug, Hash)]
pub struct Pointer {
	pub endian: Endianness,
	pub width: ByteWidth,
	pub context: Context,

	/// Describes whether this is a *mut or a *const
	///
	/// What that means exactly is not defined at this point.
	pub mutable: bool,

	/// The value or "offset" of the pointer.
	// Probably not actually needed or relevant? Value is in the data, not the def
	pub value: u64,

	/// Describes the type of data behind the pointer.
	///
	/// `None` does not mean that the pointer is opaque: this is indicated by `Some(Def::Opaque)`.
	pub def: Option<Box<Def>>,
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

impl Castable for Pointer {
	fn cast_to_string(&self, raw: &[u8]) -> Result<String, CastError> {
		Integral {
			signed: false,
			endian: self.endian,
			width: self.width,
		}
		.cast_to_string(raw)
	}
}

impl From<Pointer> for Def {
	fn from(inner: Pointer) -> Self {
		Self::Pointer(inner)
	}
}

impl From<Pointer> for Value {
	fn from(native: Pointer) -> Self {
		let mut def = vec![
			Self::symbol("pointer"),
			sexp_pair(Self::symbol("endian"), native.endian),
			sexp_pair(Self::symbol("width"), native.width.get()),
		];

		if native.mutable {
			def.push(sexp_pair(Self::symbol("mutable"), true));
		}

		if let Some(typ) = native.def {
			def.push(sexp_pair(Self::symbol("points-to"), *typ));
		}

		def.push(Self::Number(native.value.into()));
		Self::list(def)
	}
}

impl Parse for Pointer {
	fn from_sexp(sexp: &Value) -> Result<Self, ParseError> {
		let endian = parse::endianness_field(&sexp, "endian")?.unwrap_or_default();
		let width = parse::required("width", parse::nonzero_u8_field(&sexp, "width")?)?;
		let context = parse::required("context", parse::sym_field(&sexp, "context"))?.parse()?;

		let mutable = parse::bool_field(&sexp, "mutable").unwrap_or(false);

		let def = match parse::field(&sexp, "points-to") {
			Some(d) => Some(Box::new(Def::from_sexp(d)?)),
			None => None,
		};

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
			mutable,
			value,
			def,
		})
	}
}
