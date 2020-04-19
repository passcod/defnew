use crate::def::{self, Boolean, ByteWidth, Def, Endianness, Float, Integral};

pub const ENDIAN: Endianness = Endianness::Little;
pub const POINTER_WIDTH: u8 = 8;

pub fn parse_type(typestr: &str) -> Option<Def> {
	Some(match typestr {
		"usize" => u64(),
		"isize" => i64(),
		_ => return None,
	})
}

pub const fn bool() -> Def {
	Def::Boolean(Boolean {
		width: unsafe { ByteWidth::new_unchecked(1) },
	})
}

pub const fn f32() -> Def {
	use def::float::Format;

	Def::Float(Float {
		format: Format::Binary32,
		endian: Endianness::Little,
		align: None,
	})
}

pub const fn f64() -> Def {
	use def::float::Format;

	Def::Float(Float {
		format: Format::Binary64,
		endian: Endianness::Little,
		align: None,
	})
}

macro_rules! integral {
	($name:ident, $signed:expr, $width:expr) => {
		pub const fn $name() -> Def {
			Def::Integral(Integral {
				signed: $signed,
				endian: Endianness::Little,
				width: unsafe { ByteWidth::new_unchecked($width) },
			})
		}
	};
}

integral!(u8, false, 1);
integral!(u16, false, 2);
integral!(u32, false, 4);
integral!(u64, false, 8);
integral!(u128, false, 16);

integral!(i8, true, 1);
integral!(i16, true, 2);
integral!(i32, true, 4);
integral!(i64, true, 8);
integral!(i128, true, 16);
