#[macro_use]
extern crate clap;

use clap::{App, Arg};
use defnew::{
	def::{castable::Castable, layout::Layable, Def, Family},
	platform,
};
use lexpr::Value;
use std::str::FromStr;

fn main() -> Result<(), Box<dyn std::error::Error>> {
	let args = App::new("defnew")
		.author(env!("CARGO_PKG_HOMEPAGE"))
		.about("new: reads bytes from stdin and parses them according to a given def")
		.version(clap::crate_version!())
		.arg(
			Arg::with_name("output-format")
				.long("output")
				.short("o")
				.possible_values(&["kv", "env", "json"])
				.default_value("kv")
				.help("Format to output data as"),
		)
		.arg(
			Arg::with_name("with-types")
				.long("with-types")
				.help("Add output entries containing type information for each field"),
		)
		.arg(
			Arg::with_name("with-raw")
				.long("with-raw")
				.help("Add output entries containing raw bytes for each field"),
		)
		.arg(
			Arg::with_name("def")
				.takes_value(true)
				.value_name("s-exp")
				.required(true)
				.help("Type definition"),
		)
		.get_matches();

	let typestr = value_t!(args, "def", String).unwrap_or_else(|e| e.exit());

	let def = platform::parse_native_type(&typestr)
		.ok_or(clap::ErrorKind::InvalidValue)
		.or_else(|_| Def::from_str(&typestr))
		.unwrap_or_else(|err| {
			clap::Error::with_description(&err.to_string(), clap::ErrorKind::InvalidValue).exit()
		});

	let layout = def.layout();

	let bytes: &[u8] = &[
		0x00, 0x01, 0x00, 0x00, 0x00, 0x2a, 0x00, 0x00, 0xeb, 0x85, 0xb8, 0x51, 0xf6, 0x0e, 0x40,
		0xdb, 0x2f, 0x1e, 0xc7, 0xb6, 0x00, 0x00, 0x00, 0x00,
	];

	let fields = layout.fold(false, |_, parents, lay, layname| {
		if let Family::Structural = lay.def.family() {
			None
		} else {
			let mut name = parents
				.iter()
				.map(|(_, name)| name.clone())
				.collect::<Vec<String>>();
			name.push(layname.into());

			let raw = lay.extract_from_slice(bytes);
			let value = def.cast_to_string(&raw).expect("bad data");

			Some(Field {
				name,
				typename: lay.def.typename(),
				def: lay.def.as_ref().clone().into(),
				raw,
				value,
			})
		}
	});

	dbg!(&fields);

	Ok(())
}

#[derive(Clone, Debug)]
struct Field {
	name: Vec<String>,
	typename: &'static str,
	def: Value,
	raw: Vec<u8>,
	value: String,
}
