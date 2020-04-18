use lexpr::Value;

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
