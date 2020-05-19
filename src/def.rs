use alignment::Alignable;
use castable::{CastError, Castable};
use fillable::{FillError, Fillable};
use layout::{Layable, Layout};
use lexpr::Value;
use parse::Parse;
use std::{
	fmt,
	num::{NonZeroU64, NonZeroU8},
	str::FromStr,
};

pub use alignment::Alignment;
pub use array::Array;
pub use boolean::Boolean;
pub use endianness::Endianness;
pub use float::Float;
pub use integral::Integral;
pub use pointer::Pointer;
pub use r#enum::Enum;
pub use r#struct::Struct;
pub use r#union::Union;

pub mod alignment;
pub mod array;
pub mod boolean;
pub mod castable;
pub mod endianness;
pub mod r#enum;
pub mod fillable;
pub mod float;
pub mod integral;
pub mod layout;
pub mod parse;
pub mod pointer;
pub mod r#struct;
pub mod r#union;

pub type BitWidth = NonZeroU64;
pub type ByteWidth = NonZeroU8;

pub(crate) fn sexp_pair(a: impl Into<Value>, b: impl Into<Value>) -> Value {
	Value::list(vec![a.into(), b.into()])
}

pub(crate) fn div_round_up<T>(value: T, divisor: T) -> T
where
	T: std::ops::Div<Output = T>
		+ std::ops::Rem<Output = T>
		+ std::ops::Add<Output = T>
		+ std::cmp::PartialOrd
		+ From<u8>
		+ Copy,
{
	let div = value / divisor;
	let rem = value % divisor;
	div + if rem > T::from(0) {
		T::from(1)
	} else {
		T::from(0)
	}
}

#[derive(Clone, Debug, Hash)]
pub enum Def {
	// scalar:
	Boolean(Boolean),
	Integral(Integral),
	Float(Float),

	// shared:
	Enum(Enum),
	Union(Union),

	// structural:
	Struct(Struct),
	Array(Array),

	// special:
	Opaque,
	Pointer(Pointer),
	Padding(BitWidth),
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Family {
	Scalar,
	Shared,
	Structural,
	Special,
}

impl Def {
	pub fn family(&self) -> Family {
		match self {
			Def::Boolean(_) => Family::Scalar,
			Def::Integral(_) => Family::Scalar,
			Def::Float(_) => Family::Scalar,

			Def::Enum(_) => Family::Shared,
			Def::Union(_) => Family::Shared,

			Def::Struct(_) => Family::Structural,
			Def::Array(_) => Family::Structural,

			Def::Opaque => Family::Special,
			Def::Pointer(_) => Family::Special,
			Def::Padding(_) => Family::Special,
		}
	}

	pub fn typename(&self) -> &'static str {
		match self {
			Def::Boolean(_) => "boolean",
			Def::Integral(_) => "integral",
			Def::Float(_) => "float",

			Def::Enum(_) => "enum",
			Def::Union(_) => "union",

			Def::Struct(_) => "struct",
			Def::Array(_) => "array",

			Def::Opaque => "opaque",
			Def::Pointer(_) => "pointer",
			Def::Padding(_) => "padding",
		}
	}
}

impl Alignable for Def {
	fn align(&self) -> Alignment {
		match self {
			Def::Boolean(b) => b.align(),
			Def::Integral(i) => i.align(),
			Def::Float(f) => f.align(),

			Def::Enum(e) => e.align(),
			Def::Union(u) => u.align(),

			Def::Struct(s) => s.align(),
			Def::Array(a) => a.align(),

			Def::Opaque => unsafe { Alignment::new_unchecked(1_u8) },
			Def::Pointer(p) => p.align(),
			Def::Padding(bits) => {
				// Padding doesn't really have an alignment
				Alignment::from_size(div_round_up(bits.get(), 8)).unwrap_or_default()
			}
		}
	}
}

impl Layable for Def {
	fn layout(&self) -> Layout {
		match self {
			Def::Boolean(b) => b.layout(),
			Def::Integral(i) => i.layout(),
			Def::Float(f) => f.layout(),

			Def::Enum(e) => e.layout(),
			Def::Union(u) => u.layout(),

			Def::Struct(s) => s.layout(),
			Def::Array(a) => a.layout(),

			Def::Opaque => Layout::default(),
			Def::Pointer(p) => p.layout(),
			Def::Padding(bits) => {
				let mut layout = Layout::default();
				layout.pad(*bits);
				layout
			}
		}
	}
}

impl Fillable for Def {
	fn fill_from_str(&self, s: &str) -> Result<Vec<u8>, FillError> {
		match self {
			Def::Boolean(b) => b.fill_from_str(s),
			Def::Integral(i) => i.fill_from_str(s),
			Def::Float(f) => f.fill_from_str(s),

			Def::Enum(e) => e.fill_from_str(s),
			Def::Union(u) => u.fill_from_str(s),

			Def::Opaque => unreachable!("opaque cannot be created"),
			Def::Pointer(p) => p.fill_from_str(s),
			Def::Struct(_) | Def::Array(_) | Def::Padding(_) => {
				unreachable!("structural or padding defs are not filled directly")
			}
		}
	}
}

impl Castable for Def {
	fn cast_to_string(&self, raw: &[u8]) -> Result<String, CastError> {
		match self {
			Def::Boolean(b) => b.cast_to_string(raw),
			Def::Integral(i) => i.cast_to_string(raw),
			Def::Float(f) => f.cast_to_string(raw),

			Def::Enum(e) => e.cast_to_string(raw),
			Def::Union(u) => u.cast_to_string(raw),

			Def::Opaque => Ok(String::from("opaque")),
			Def::Pointer(p) => p.cast_to_string(raw),
			Def::Struct(_) | Def::Array(_) | Def::Padding(_) => {
				unreachable!("structural or padding defs are not cast directly")
			}
		}
	}
}

impl From<Def> for Value {
	fn from(native: Def) -> Self {
		match native {
			Def::Boolean(native) => native.into(),
			Def::Integral(native) => native.into(),
			Def::Float(native) => native.into(),

			Def::Enum(native) => native.into(),
			Def::Union(native) => native.into(),

			Def::Struct(native) => native.into(),
			Def::Array(native) => native.into(),

			Def::Opaque => Self::list(vec![Self::symbol("opaque")]),
			Def::Padding(bits) => Self::list(vec![Self::symbol("padding"), bits.get().into()]),
			Def::Pointer(native) => native.into(),
		}
	}
}

impl fmt::Display for Def {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		let sexp: Value = self.clone().into();
		sexp.fmt(f)
	}
}

impl FromStr for Def {
	type Err = parse::ParseError;

	fn from_str(s: &str) -> Result<Self, Self::Err> {
		Self::from_sexp(&lexpr::from_str(s)?)
	}
}
