use thiserror::Error;

pub trait Castable {
	fn cast_to_string(&self, raw: &[u8]) -> Result<String, CastError>;
}

#[derive(Debug, Error)]
pub enum CastError {
	#[error("{0}")]
	InvalidLength(#[from] std::array::TryFromSliceError),

	#[error("enum value is too large for a u64 (unsupported)")]
	EnumValueTooLarge,
}
