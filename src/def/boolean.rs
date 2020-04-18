use super::{
	alignment::{Alignable, Alignment},
	layout::{CowDef, Layable, Layout},
	sexp_pair, ByteWidth, Def,
};
use lexpr::Value;

// TODO: reconsider bit patterns
//
// #[derive(Clone, Copy, Debug)]
// pub enum Bit {
// 	One,
// 	Zero,
// 	Undef,
// }

// #[derive(Clone, Debug)]
// pub struct BitPattern(pub Vec<Bit>);

// impl From<BitPattern> for Value {
// 	fn from(native: BitPattern) -> Self {
// 		let pat: String = native
// 			.0
// 			.iter()
// 			.map(|bit| match bit {
// 				Bit::One => '1',
// 				Bit::Zero => '0',
// 				Bit::Undef => '_',
// 			})
// 			.collect();
// 		Self::string(pat)
// 	}
// }

#[derive(Clone, Debug)]
pub struct Boolean {
	pub width: ByteWidth,
	// pub true_pattern: Option<BitPattern>,
	// pub false_pattern: Option<BitPattern>,
}

impl Default for Boolean {
	fn default() -> Self {
		Self {
			width: unsafe { ByteWidth::new_unchecked(1) },
			// true_pattern: None,
			// false_pattern: None,
		}
	}
}

impl Alignable for Boolean {
	fn align(&self) -> Alignment {
		Alignment::from_size(u64::from(self.width.get()))
			.expect("non-zero u8 did not fit in non-zero u64???")
	}
}

impl Layable for Boolean {
	fn layout(&self) -> Layout {
		let size = u64::from(self.width.get());
		let mut layout = Layout::default();
		layout.append_with_size(CowDef::Owned(self.clone().into()), size * 8);
		layout
	}
}

impl From<Boolean> for Def {
	fn from(inner: Boolean) -> Self {
		Self::Boolean(inner)
	}
}

impl From<Boolean> for Value {
	fn from(native: Boolean) -> Self {
		let mut def = vec![Self::symbol("bool")];

		if native.width != Boolean::default().width {
			def.push(sexp_pair(Self::symbol("width"), native.width.get()));
		}

		// if let Some(pattern) = native.true_pattern {
		// 	def.push(sexp_pair(Self::symbol("true-pattern"), pattern));
		// }

		// if let Some(pattern) = native.false_pattern {
		// 	def.push(sexp_pair(Self::symbol("false-pattern"), pattern));
		// }

		Self::list(def)
	}
}
