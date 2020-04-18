use super::Alignment;
use super::{BitWidth, Def};
use log::trace;
use std::{borrow::Cow, convert::TryInto, fmt, num::NonZeroU8};
use thiserror::Error;

pub trait Layable {
	fn layout<'def>(&'def self) -> Layout<'def>;
}

type Bits = u64;

pub type CowDef<'def> = Cow<'def, Def>;

#[derive(Clone, Debug)]
pub struct Lay<'def> {
	pub def: CowDef<'def>,
	pub offset: Bits,
	pub size: Bits,
}

#[derive(Clone, Debug, Default)]
pub struct Layout<'def> {
	pub size: Bits,
	pub lays: Vec<Lay<'def>>,
}

impl<'def> Layout<'def> {
	pub fn append_with_size(&mut self, def: CowDef<'def>, size: Bits) {
		trace!(
			"{:03} -> {:03}  = {:3}   [{:?}]",
			self.size,
			self.size + size,
			size,
			&def
		);

		self.lays.push(Lay {
			def,
			offset: self.size,
			size,
		});
		self.size += size;
	}

	pub fn append(&mut self, def: CowDef<'def>) {
		let size = def.layout().size;
		self.append_with_size(def, size);
	}

	pub fn pad(&mut self, bits: impl Into<Bits>) {
		let mut bits = bits.into();
		if bits == 0 {
			return;
		}

		// extend existing padding if present
		if let Some(
			existing @ Lay {
				def: CowDef::Owned(Def::Padding(_)),
				..
			},
		) = self.lays.last()
		{
			bits += existing.size;
			self.lays.pop();
		}

		if let Some(padding) = BitWidth::new(bits) {
			self.append_with_size(CowDef::Owned(Def::Padding(padding)), bits);
		}
	}

	pub fn pad_to(&mut self, size: Bits) {
		if size > self.size {
			self.pad(size - self.size);
		}
	}

	pub fn bytes(&self) -> Result<u64, PartialByte> {
		let rem = self.size % 8;
		if rem == 0 {
			Ok(self.size / 8)
		} else {
			Err(PartialByte {
				bits: rem
					.try_into()
					.ok()
					.and_then(NonZeroU8::new)
					.expect("(n % 8) didn't fit in u8???"),
			})
		}
	}

	pub fn pad_to_align(&mut self, align: Alignment) {
		let align = align.as_u64() * 8;
		if let Some(bits) = self.size.checked_rem(align) {
			if bits == 0 {
				return;
			}
			trace!("align  pad {:3} % {:3} = {:3}", self.size, align, bits);
			self.pad(align - bits);
		}
	}

	pub fn is_zero_sized(&self) -> bool {
		self.size == 0
	}
}

impl<'def> fmt::Display for Layout<'def> {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		for lay in &self.lays {
			writeln!(
				f,
				"{:08} -> {:08} {:7} bytes  [{:?}]",
				lay.offset,
				lay.offset + lay.size,
				lay.size / 8,
				lay.def
			)?;

			let inner = lay.def.layout();
			if inner.lays.len() > 1 {
				writeln!(
					f,
					"{}",
					inner
						.to_string()
						.lines()
						.map(|line| format!("\t{}", line))
						.fold(String::new(), |a, b| if a.is_empty() {
							a
						} else {
							a + "\n"
						} + &b)
				)?;
			}
		}

		Ok(())
	}
}

#[derive(Clone, Copy, Debug, Error)]
#[error("layout does not align to bytes")]
pub struct PartialByte {
	pub bits: NonZeroU8,
}

impl PartialByte {
	pub fn counter(self) -> u8 {
		8 - self.bits.get()
	}
}
