use lexpr::Value;
use std::{
	fmt,
	num::{NonZeroU64, ParseIntError},
	str::FromStr,
};
use thiserror::Error;

pub trait Alignable {
	fn align(&self) -> Alignment;
}

// "The alignment value must be a power of two from 1 up to 2^29."
// https://doc.rust-lang.org/stable/reference/type-layout.html#the-alignment-modifiers

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialOrd, PartialEq)]
pub struct Alignment(pub NonZeroU64);

impl Alignment {
	pub unsafe fn new_unchecked(n: impl Into<u64>) -> Self {
		Self(NonZeroU64::new_unchecked(n.into()))
	}

	pub fn from_size(size: impl Into<u64>) -> Result<Self, InvalidAlignmentError> {
		let size = size.into();

		if size.is_power_of_two() {
			Self::new(size)
		} else if let Some(next_power) = size.checked_next_power_of_two() {
			Self::new(next_power)
		} else {
			Err(InvalidAlignmentError(size))
		}
	}

	pub fn new(n: impl Into<u64>) -> Result<Self, InvalidAlignmentError> {
		let n = n.into();
		let nz = NonZeroU64::new(n).ok_or(InvalidAlignmentError(n))?;

		if !n.is_power_of_two() {
			Err(InvalidAlignmentError(n))?;
		}

		if let Some(next_power) = n.checked_next_power_of_two() {
			if next_power > 30 {
				Err(InvalidAlignmentError(n))
			} else {
				Ok(Self(nz))
			}
		} else {
			Err(InvalidAlignmentError(n))
		}
	}

	pub fn as_u64(self) -> u64 {
		self.into()
	}

	pub fn increase_to(&mut self, other: Self) {
		self.0 = self.clone().max(other).0;
	}
}

impl Default for Alignment {
	fn default() -> Self {
		unsafe { Self::new_unchecked(1_u64) }
	}
}

impl fmt::Display for Alignment {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		self.0.fmt(f)
	}
}

impl From<Alignment> for u64 {
	fn from(a: Alignment) -> Self {
		a.0.get()
	}
}

impl From<Alignment> for NonZeroU64 {
	fn from(a: Alignment) -> Self {
		a.0
	}
}

impl From<Alignment> for Value {
	fn from(align: Alignment) -> Self {
		Self::Number(align.0.get().into())
	}
}

impl FromStr for Alignment {
	type Err = ParseAlignmentError;

	fn from_str(s: &str) -> Result<Self, Self::Err> {
		let nz: NonZeroU64 = s
			.parse()
			.map_err(|err| ParseAlignmentError::NonZeroInt(err))?;
		Alignment::new(nz).map_err(|err| ParseAlignmentError::Alignment(err))
	}
}

#[derive(Debug, Error)]
#[error("alignment must be a power of two from 1 up to 2^29")]
pub enum ParseAlignmentError {
	NonZeroInt(ParseIntError),
	Alignment(InvalidAlignmentError),
}

#[derive(Clone, Copy, Debug, Error)]
#[error("alignment must be a power of two from 1 up to 2^29")]
pub struct InvalidAlignmentError(pub u64);
