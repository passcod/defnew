#[macro_use]
extern crate clap;

use clap::{App, Arg};
use defnew::{
	def::{
		layout::{Layable, Layout},
		Def, Family,
	},
	platform,
};
use std::str::FromStr;

fn main() -> Result<(), Box<dyn std::error::Error>> {
	let args = App::new("defnew")
		.author(env!("CARGO_PKG_HOMEPAGE"))
		.about("new: given a def and some values (missing ones default to zeroed), outputs bytes")
		.version(clap::crate_version!())
		.arg(
			Arg::with_name("show-paths")
				.long("show-paths")
				.short("P")
				.help("Shows field paths for the def given"),
		)
		.arg(
			Arg::with_name("def")
				.takes_value(true)
				.value_name("s-exp")
				.required(true)
				.help("Type definition"),
		)
		.arg(
			Arg::with_name("values")
				.takes_value(true)
				.value_name("[path:]value")
				.multiple(true)
				.help("Values to fill in"),
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

	let values = args.values_of("values").unwrap_or_default();

	dbg!(&layout, &values);

	show_fields("", &layout);

	Ok(())
}

fn show_fields(parent: &str, layout: &Layout) {
	for (i, lay) in layout
		.lays
		.iter()
		.filter(|lay| !matches!(lay.def.as_ref(), &Def::Padding(_)))
		.enumerate()
	{
		let name = format!("{}{}", parent, lay.name.as_ref().unwrap_or(&i.to_string()));
		println!("{:30}: {:?}", name, lay.def);

		if let Family::Structural = lay.def.family() {
			show_fields(&(name + "."), &lay.def.layout());
		}
	}
}
