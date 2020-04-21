use thiserror::Error;

pub trait Fillable {
	fn fill_from_str(&self, s: &str) -> Result<Vec<u8>, FillError>;
}

#[derive(Debug, Error)]
pub enum FillError {
	#[error("union does not have this altern")]
	UnknownAltern,

	#[error("enum does not have this variant")]
	UnknownVariant,

	#[error("{0}")]
	ParseInt(#[from] std::num::ParseIntError),

	#[error("{0}")]
	ParseFloat(#[from] std::num::ParseFloatError),
}
