use lexpr::Value;
use std::str::FromStr;
use thiserror::Error;

#[derive(Clone, Copy, Debug)]
pub enum Endianness {
	Big,
	Little,
	Native,
}

impl Default for Endianness {
	fn default() -> Self {
		Self::Native
	}
}

impl From<Endianness> for Value {
	fn from(native: Endianness) -> Self {
		Self::symbol(match native {
			Endianness::Big => "big",
			Endianness::Little => "little",
			Endianness::Native => "native",
		})
	}
}

impl FromStr for Endianness {
	type Err = InvalidEndiannessError;

	fn from_str(s: &str) -> Result<Self, Self::Err> {
		match s {
			"big" => Ok(Self::Big),
			"little" => Ok(Self::Little),
			"native" => Ok(Self::Native),
			endian => Err(InvalidEndiannessError(endian.to_string())),
		}
	}
}

#[derive(Debug, Error)]
#[error("invalid endian specifier: {0} (expected one of: big, little, native)")]
pub struct InvalidEndiannessError(String);
