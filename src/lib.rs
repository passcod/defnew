use def::parse::ParseError;
use std::str::FromStr;

pub use def::Def;

pub mod def;
pub mod platform;

pub fn parse_def(typestr: &str) -> Result<Def, ParseError> {
	platform::parse_native_type(typestr)
		.ok_or_else(|| ParseError::UnknownType(typestr.into()))
		.or_else(|_| Def::from_str(&typestr))
}
