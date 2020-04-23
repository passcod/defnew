use thiserror::Error;

pub trait Castable {
	fn cast_to_string(&self, raw: &[u8]) -> Result<String, CastError>;
}

#[derive(Debug, Error)]
pub enum CastError {
	#[error("todo")]
	Todo,
}
