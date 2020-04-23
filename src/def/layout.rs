use super::Alignment;
use super::{
	div_round_up,
	fillable::{FillError, Fillable},
	BitWidth, Def, Family,
};
use log::trace;
use std::{
	borrow::Cow,
	collections::HashMap,
	convert::{TryFrom, TryInto},
	fmt,
	io::{Cursor, Write},
	num::NonZeroU8,
};
use thiserror::Error;

pub trait Layable {
	fn layout<'def>(&'def self) -> Layout<'def>;
}

type Bits = u64;

pub type CowDef<'def> = Cow<'def, Def>;

#[derive(Debug, Hash)]
pub struct Lay<'def> {
	pub name: Option<String>,
	pub def: CowDef<'def>,
	pub offset: Bits,
	pub size: Bits,
	unique: usize,
}

const SIZE_OF_LAY: &'static str = "size of lay does not fit in usize";

impl<'def> Lay<'def> {
	pub fn make_unique() -> usize {
		use std::sync::atomic::{AtomicUsize, Ordering};
		static IOTA: AtomicUsize = AtomicUsize::new(0);
		IOTA.fetch_add(1, Ordering::SeqCst)
	}

	pub fn new(
		name: Option<impl Into<String>>,
		def: CowDef<'def>,
		offset: Bits,
		size: Bits,
	) -> Self {
		Self {
			name: name.map(|s| s.into()),
			def,
			offset,
			size,
			unique: Self::make_unique(),
		}
	}

	pub fn fill_from_str(&self, s: &str) -> Result<Vec<u8>, FillError> {
		self.def.fill_from_str(s)
		// vec![0xFF; usize::try_from(div_round_up(self.size, 8)).expect(SIZE_OF_LAY)]
	}

	pub fn fill_as_zero(&self) -> Vec<u8> {
		vec![0; usize::try_from(div_round_up(self.size, 8)).expect(SIZE_OF_LAY)]
	}

	pub fn unique(&self) -> usize {
		self.unique
	}

	pub fn extract_from_slice(&self, slice: &[u8]) -> Vec<u8> {
		if self.offset % 8 != 0 {
			todo!("extraction for non-aligned lays");
		} else {
			let start = usize::try_from(self.offset / 8).expect(SIZE_OF_LAY);
			let end = usize::try_from((self.offset + self.size) / 8).expect(SIZE_OF_LAY);
			slice[start..end].to_vec()
		}
	}
}

impl<'def> Clone for Lay<'def> {
	fn clone(&self) -> Self {
		Self {
			name: self.name.clone(),
			def: self.def.clone(),
			offset: self.offset,
			size: self.size,
			unique: Self::make_unique(),
		}
	}
}

#[derive(Clone, Debug, Default)]
pub struct Layout<'def> {
	pub size: Bits,
	pub lays: Vec<Lay<'def>>,
}

impl<'def> Layout<'def> {
	// fn(abs, parents: vec<(lay, name)>, lay, name)
	pub fn fold<T>(
		&self,
		with_padding: bool,
		mut op: impl FnMut(&mut usize, &[&(&Lay, String)], &Lay, &str) -> Option<T>,
	) -> Vec<T> {
		self.fold_impl(&mut 0, &[], with_padding, &mut op)
	}

	// TODO: this entire thing (and its uses) probably needs a good rethink/refactor
	fn fold_impl<T, F>(
		&self,
		abs: &mut usize,
		parents: &[&(&Lay, String)],
		with_padding: bool,
		op: &mut F,
	) -> Vec<T>
	where
		F: FnMut(&mut usize, &[&(&Lay, String)], &Lay, &str) -> Option<T>,
	{
		let it: Vec<(usize, &Lay)> = if with_padding {
			self.lays.iter().enumerate().collect()
		} else {
			self.lays
				.iter()
				.filter(|lay| !matches!(lay.def.as_ref(), &Def::Padding(_)))
				.enumerate()
				.collect()
		};

		let mut laundry = Vec::new();
		for (rel, lay) in it {
			let name = lay.name.clone().unwrap_or(rel.to_string());

			if let Some(item) = op(abs, parents, lay, &name) {
				laundry.push(item);
			}

			*abs += 1;

			if let Family::Structural = lay.def.family() {
				let mut ps = Vec::new();
				ps.extend(parents);
				let this = (lay, name);
				ps.push(&this);

				laundry.extend(lay.def.layout().fold_impl(abs, &ps, with_padding, op));
			}
		}

		laundry
	}

	pub fn fill(
		&self,
		positional: impl IntoIterator<Item = String>,
		keyed: HashMap<Vec<String>, String>,
	) -> Result<Vec<u8>, FillError> {
		let mut positional = positional.into_iter();

		// Vec<(bytes, size in bits)>
		let fields = self
			.fold(true, |_, parents, lay, name| {
				let mut key = parents
					.iter()
					.map(|(_, name)| name.clone())
					.collect::<Vec<String>>();
				key.push(name.into());

				let size = if lay.size % 8 == 0 {
					usize::try_from(lay.size).expect(SIZE_OF_LAY)
				} else {
					todo!("partial-byte lay fills")
				};

				Some(if let Family::Structural = lay.def.family() {
					return None;
				} else if let Def::Padding(_) = lay.def.as_ref() {
					Ok((lay.fill_as_zero(), size))
				} else if let Some(value) = keyed.get(&key) {
					lay.fill_from_str(&value).map(|v| (v, size))
				} else if let Some(value) = positional.next() {
					lay.fill_from_str(&value).map(|v| (v, size))
				} else {
					Ok((lay.fill_as_zero(), size))
				})
			})
			.into_iter()
			.collect::<Result<Vec<_>, _>>()?;

		let mut buf = Cursor::new(vec![
			0;
			div_round_up(
				fields.iter().map(|(_, bits)| bits).sum(),
				8
			)
		]);

		for (bytes, _) in fields {
			buf.write(&bytes).expect("failed to write to memory???");
		}

		Ok(buf.into_inner())
	}

	pub fn append_with_size_and_name(
		&mut self,
		name: Option<String>,
		def: CowDef<'def>,
		size: Bits,
	) {
		trace!(
			"{:03} -> {:03}  = {:3}   ({:?}) [{:?}]",
			self.size,
			self.size + size,
			size,
			&name,
			&def
		);

		self.lays.push(Lay::new(name, def, self.size, size));
		self.size += size;
	}

	pub fn append_with_size(&mut self, def: CowDef<'def>, size: Bits) {
		self.append_with_size_and_name(None, def, size);
	}

	pub fn append_with_name(&mut self, name: Option<String>, def: CowDef<'def>) {
		let size = def.layout().size;
		self.append_with_size_and_name(name, def, size);
	}

	pub fn append(&mut self, def: CowDef<'def>) {
		self.append_with_name(None, def);
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
