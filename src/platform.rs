use crate::def::Def;

pub mod x86_64;
// pub mod x86; etc

cfg_if::cfg_if! {
	if #[cfg(target_arch = "x86_64")] {
		pub use x86_64 as native;
	} else {
		compile_error!("no implementation of native types");
	}
}

pub fn parse_native_type(typestr: &str) -> Option<Def> {
	Some(match typestr {
		"bool" => native::bool(),

		"u8" => native::u8(),
		"u16" => native::u16(),
		"u32" => native::u32(),
		"u64" => native::u64(),
		"u128" => native::u128(),

		"i8" => native::i8(),
		"i16" => native::i16(),
		"i32" => native::i32(),
		"i64" => native::i64(),
		"i128" => native::i128(),

		"f32" => native::f32(),
		"f64" => native::f64(),

		typestr => return native::parse_type(typestr),
	})
}
