use super::{
	alignment::{Alignment, InvalidAlignmentError},
	endianness::{Endianness, InvalidEndiannessError},
	float::{Float, InvalidFloatFormatError},
	pointer::{InvalidContextError, Pointer},
	Array, Boolean, Def, Enum, Integral, Struct, Union,
};
use lexpr::Value;
use std::{
	convert::TryFrom,
	num::{NonZeroU64, NonZeroU8},
	str::FromStr,
};
use thiserror::Error;

pub(crate) fn required<T>(name: &'static str, value: Option<T>) -> Result<T, ParseError> {
	value.ok_or(ParseError::MissingField(String::from(name)))
}

pub(crate) fn field<'v>(sexp: &'v Value, name: &'static str) -> Option<&'v Value> {
	sexp.get(name).and_then(|s| s.get(0))
}

pub(crate) fn u64_field<'v>(sexp: &'v Value, name: &'static str) -> Option<u64> {
	field(sexp, name).and_then(|s| s.as_u64())
}

pub(crate) fn bool_field<'v>(sexp: &'v Value, name: &'static str) -> Option<bool> {
	field(sexp, name).and_then(|s| s.as_bool())
}

pub(crate) fn str_field<'v>(sexp: &'v Value, name: &'static str) -> Option<&'v str> {
	field(sexp, name).and_then(|s| s.as_str())
}

pub(crate) fn sym_field<'v>(sexp: &'v Value, name: &'static str) -> Option<&'v str> {
	field(sexp, name).and_then(|s| s.as_symbol())
}

macro_rules! nonzero_field {
	($name:ident, $n:ty, $nz:ty) => {
		pub(crate) fn $name<'v>(
			sexp: &'v Value,
			name: &'static str,
		) -> Result<Option<$nz>, ParseError> {
			match u64_field(sexp, name).map(|n| {
				<$n>::try_from(n)
					.or(Err(ParseError::LargerThanType(stringify!($n))))
					.and_then(|n| {
						<$nz>::new(n).ok_or_else(|| ParseError::NonZeroField(name.into()))
					})
			}) {
				None => Ok(None),
				Some(Ok(width)) => Ok(Some(width)),
				Some(Err(err)) => Err(err),
			}
		}
	};
}

nonzero_field!(nonzero_u8_field, u8, NonZeroU8);
nonzero_field!(nonzero_u64_field, u64, NonZeroU64);

pub(crate) fn alignment_field<'v>(
	sexp: &'v Value,
	name: &'static str,
) -> Result<Option<Alignment>, ParseError> {
	match u64_field(sexp, name).map(Alignment::new) {
		None => Ok(None),
		Some(Ok(align)) => Ok(Some(align)),
		Some(Err(err)) => Err(err.into()),
	}
}

pub(crate) fn endianness_field<'v>(
	sexp: &'v Value,
	name: &'static str,
) -> Result<Option<Endianness>, ParseError> {
	match sym_field(sexp, name).map(Endianness::from_str) {
		None => Ok(None),
		Some(Ok(endian)) => Ok(Some(endian)),
		Some(Err(err)) => Err(err.into()),
	}
}

pub trait Parse {
	fn from_sexp(sexp: &Value) -> Result<Self, ParseError>
	where
		Self: Sized;
}

impl Parse for Def {
	fn from_sexp(sexp: &Value) -> Result<Self, ParseError> {
		if !sexp.is_list() {
			Err(ParseError::NotAList)?;
		}

		let head = if let Value::Symbol(head) = sexp.get(0).ok_or(ParseError::EmptyList)? {
			head
		} else {
			return Err(ParseError::NoSymbolType);
		};

		let args = Value::list(
			sexp.to_vec()
				.ok_or(ParseError::EmptyList)?
				.into_iter()
				.skip(1),
		);

		match head.as_ref() {
			"bool" => Ok(Def::Boolean(Boolean::from_sexp(&args)?)),
			"integral" => Ok(Def::Integral(Integral::from_sexp(&args)?)),
			"float" => Ok(Def::Float(Float::from_sexp(&args)?)),

			"struct" => Ok(Def::Struct(Struct::from_sexp(&args)?)),
			"enum" => Ok(Def::Enum(Enum::from_sexp(&args)?)),
			"union" => Ok(Def::Union(Union::from_sexp(&args)?)),
			"array" => Ok(Def::Array(Array::from_sexp(&args)?)),

			"pointer" => Ok(Def::Pointer(Pointer::from_sexp(&args)?)),
			"padding" => args
				.get(0)
				.and_then(|v| v.as_u64())
				.ok_or_else(|| ParseError::MissingField("<padding length>".into()))
				.and_then(|n| {
					NonZeroU64::new(n)
						.ok_or_else(|| ParseError::NonZeroField("<padding length>".into()))
				})
				.map(Def::Padding),

			typ => match crate::platform::parse_native_type(typ) {
				Some(def) => Ok(def),
				None => Err(ParseError::UnknownType(typ.into())),
			},
		}
	}
}

#[derive(Debug, Error)]
pub enum ParseError {
	#[error("s-expression invalid")]
	Sexp(#[from] lexpr::parse::Error),

	#[error("s-expression is not a list")]
	NotAList,

	#[error("list is empty")]
	EmptyList,

	#[error("def type (first element of list) is not a symbol")]
	NoSymbolType,

	#[error("def type is unknown: {0}")]
	UnknownType(String),

	#[error("required field is missing: {0}")]
	MissingField(String),

	#[error("field value is larger than {0}")]
	LargerThanType(&'static str),

	#[error("field {0} is zero, but must not")]
	NonZeroField(String),

	#[error("enum discriminant is not a number")]
	EnumDiscriminantNaN,

	#[error("field is not proper alignment")]
	Alignment(#[from] InvalidAlignmentError),

	#[error("field is not proper endianness")]
	Endian(#[from] InvalidEndiannessError),

	#[error("field is not proper float format")]
	FloatFormat(#[from] InvalidFloatFormatError),

	#[error("field is not proper pointer context")]
	PointerContext(#[from] InvalidContextError),
}
