use alignment::Alignable;
use layout::{Layable, Layout};
use lexpr::Value;
use parse::Parse;
use std::{
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
pub mod endianness;
pub mod r#enum;
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

pub(crate) fn div_round_up(value: u64, divisor: u64) -> u64 {
	let div = value / divisor;
	let rem = value % divisor;
	div + if rem > 0 { 1 } else { 0 }
}

#[derive(Clone, Debug)]
pub enum Def {
	// scalar:
	Boolean(Boolean),
	Integral(Integral),
	Float(Float),

	// structural:
	Struct(Struct),
	Enum(Enum),
	Union(Union),
	Array(Array),

	// special:
	Pointer(Pointer),
	Padding(BitWidth),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Family {
	Scalar,
	Structural,
	Special,
}

impl Def {
	pub fn family(&self) -> Family {
		match self {
			Def::Boolean(_) => Family::Scalar,
			Def::Integral(_) => Family::Scalar,
			Def::Float(_) => Family::Scalar,

			Def::Struct(_) => Family::Structural,
			Def::Enum(_) => Family::Structural,
			Def::Union(_) => Family::Structural,
			Def::Array(_) => Family::Structural,

			Def::Pointer(_) => Family::Special,
			Def::Padding(_) => Family::Special,
		}
	}
}

impl Alignable for Def {
	fn align(&self) -> Alignment {
		match self {
			Def::Boolean(b) => b.align(),
			Def::Integral(i) => i.align(),
			Def::Float(f) => f.align(),

			Def::Struct(s) => s.align(),
			Def::Enum(e) => e.align(),
			Def::Union(u) => u.align(),
			Def::Array(a) => a.align(),

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

			Def::Struct(s) => s.layout(),
			Def::Enum(e) => e.layout(),
			Def::Union(u) => u.layout(),
			Def::Array(a) => a.layout(),

			Def::Pointer(p) => p.layout(),
			Def::Padding(bits) => {
				let mut layout = Layout::default();
				layout.pad(*bits);
				layout
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

			Def::Struct(native) => native.into(),
			Def::Enum(native) => native.into(),
			Def::Union(native) => native.into(),
			Def::Array(native) => native.into(),

			Def::Padding(bits) => Self::list(vec![Self::symbol("padding"), bits.get().into()]),
			Def::Pointer(native) => native.into(),
		}
	}
}

impl FromStr for Def {
	type Err = parse::ParseError;

	fn from_str(s: &str) -> Result<Self, Self::Err> {
		Self::from_sexp(&lexpr::from_str(s)?)
	}
}
