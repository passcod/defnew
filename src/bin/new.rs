use clap::{App, Arg};
use defnew::{
	def::{
		layout::{Layable, Layout},
		Family,
	},
	parse_def,
};
use std::{
	collections::HashMap,
	fs::File,
	io::{stdout, Write},
};

fn main() -> color_eyre::Result<()> {
	let args = App::new("defnew")
		.author(&*format!(
			"CC BY-SA-NC 4.0 - {}",
			env!("CARGO_PKG_HOMEPAGE")
		))
		.about("new: given a def and some values (missing ones default to zeroed), outputs bytes")
		.version(clap::crate_version!())
		.arg(
			Arg::new("show-fields")
				.long("show-fields")
				.short('F')
				.about("Shows field paths for the def given instead"),
		)
		.arg(
			Arg::new("file")
				.long("output")
				.short('o')
				.takes_value(true)
				.value_name("path")
				.about("Writes to file instead of stdout"),
		)
		.arg(
			Arg::new("def")
				.takes_value(true)
				.value_name("s-exp")
				.required(true)
				.about("Type definition"),
		)
		.arg(
			Arg::new("values")
				.takes_value(true)
				.value_name("[path:]value")
				.multiple(true)
				.about("Values to fill in"),
		)
		.get_matches();

	let typestr: String = args.value_of_t("def").unwrap_or_else(|e| e.exit());

	let def = parse_def(&typestr)?;

	let layout = def.layout();

	let values = args.values_of("values").unwrap_or_default();

	if args.is_present("show-fields") {
		eprintln!("[ARG]  {:<35}  DESCRIPTION", "STRUCTURAL PATH");
		for (arg, path, desc) in show_fields(&layout) {
			eprintln!(
				"[{:>3}]  {:35}  {}",
				arg.map_or(String::new(), |n| n.to_string()),
				arg.map_or(String::new(), |_| path),
				desc
			);
		}

		return Ok(());
	}

	let mut positional = Vec::new();
	let mut keyed = HashMap::new();

	for v in values {
		match v.splitn(2, ":").collect::<Vec<&str>>().as_slice() {
			[key, value] if key.parse::<usize>().is_ok() => positional.push((*value).into()),
			[key, value] => {
				keyed.insert(key_from_path(*key), (*value).into());
			}
			[value] => positional.push((*value).into()),
			_ => unreachable!(),
		}
	}

	let bytes = layout.fill(positional, keyed)?;

	if let Some(file) = args.value_of_os("file") {
		let mut file = File::create(file)?;
		file.write_all(&bytes)?;
	} else {
		stdout().write_all(&bytes)?;
	}

	Ok(())
}

fn show_fields(layout: &Layout) -> Vec<(Option<usize>, String, String)> {
	layout.fold(false, |abs, parents, lay, name| {
		let mut fullname = parents
			.iter()
			.map(|(_, name)| name.clone())
			.collect::<Vec<String>>();
		fullname.insert(0, "".into());
		let fullname = fullname.join(".");

		Some((
			if let Family::Structural = lay.def.family() {
				*abs -= 1;
				None
			} else {
				Some(*abs)
			},
			format!("{}.{}", fullname, name),
			format!("{:?}", lay.def)
				.chars()
				.take(120)
				.collect::<String>(),
		))
	})
}

fn key_from_path(path: &str) -> Vec<String> {
	path.split(".")
		.filter_map(|k| if k.is_empty() { None } else { Some(k.into()) })
		.collect()
}
