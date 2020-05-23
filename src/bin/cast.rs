use clap::{App, Arg};
use defnew::{
	def::{castable::Castable, layout::Layable, Family},
	parse_def,
};
use lexpr::Value;
use std::{
	convert::Infallible,
	fs::File,
	io::{stdin, BufReader, Read},
	str::FromStr,
};
use thiserror::Error;

fn main() -> color_eyre::Result<()> {
	let args = App::new("defnew")
		.author(&*format!(
			"CC BY-SA-NC 4.0 - {}",
			env!("CARGO_PKG_HOMEPAGE")
		))
		.about("cast: reads bytes from stdin and parses them according to a given def")
		.version(clap::crate_version!())
		.arg(
			Arg::new("file")
				.long("file")
				.short('f')
				.takes_value(true)
				.about("File to read data from instead of stdin"),
		)
		.arg(
			Arg::new("output-format")
				.long("output")
				.short('o')
				.possible_values(&["plain", "env"])
				.default_value("plain")
				.about("Format to output data as"),
		)
		.arg(
			Arg::new("with-types")
				.long("with-types")
				.about("Add output entries containing basic type names for each field"),
		)
		.arg(
			Arg::new("with-defs")
				.long("with-defs")
				.about("Add output entries containing type defs for each field"),
		)
		.arg(
			Arg::new("with-raws")
				.long("with-raws")
				.about("Add output entries containing raw bytes for each field"),
		)
		.arg(
			Arg::new("def")
				.takes_value(true)
				.value_name("def s-exp")
				.required(true)
				.about("Type definition"),
		)
		.get_matches();

	let typestr: String = args.value_of_t("def").map_err(ClapError)?;

	let def = parse_def(&typestr)?;

	let layout = def.layout();

	let bytes = if let Some(file) = args.value_of_os("file") {
		let file = File::open(file)?;
		let mut buf = BufReader::new(file);
		let mut bytes = Vec::new();
		buf.read_to_end(&mut bytes)?;
		bytes
	} else {
		let mut bytes = Vec::new();
		stdin().read_to_end(&mut bytes)?;
		bytes
	};

	let fields = layout.fold(false, |_, parents, lay, layname| {
		if let Family::Structural = lay.def.family() {
			None
		} else {
			let mut name = parents
				.iter()
				.map(|(_, name)| name.clone())
				.collect::<Vec<String>>();
			name.push(layname.into());

			let mut bytes = bytes.to_vec();
			for (parent, _) in parents {
				bytes = parent.extract_from_slice(&bytes);
			}

			let raw = lay.extract_from_slice(&bytes);
			let value = lay.def.cast_to_string(&raw).expect("bad data");

			Some(Field {
				name,
				typename: lay.def.typename(),
				def: lay.def.as_ref().clone().into(),
				raw,
				value,
			})
		}
	});

	let format = args.value_of_t("output-format").map_err(ClapError)?;

	let with = With {
		types: args.is_present("with-types"),
		defs: args.is_present("with-defs"),
		raws: args.is_present("with-raws"),
	};

	for field in fields {
		match format {
			Format::Plain => render_plain(field, with),
			Format::Env => render_env(field, with),
		}
	}

	Ok(())
}

#[derive(Debug, Error)]
#[error("argument error: {0}")]
struct ClapError(clap::Error);

#[derive(Clone, Debug)]
struct Field {
	name: Vec<String>,
	typename: &'static str,
	def: Value,
	raw: Vec<u8>,
	value: String,
}

#[derive(Clone, Copy, Debug)]
struct With {
	pub types: bool,
	pub defs: bool,
	pub raws: bool,
}

#[derive(Clone, Copy, Debug)]
enum Format {
	Plain,
	Env,
}

impl FromStr for Format {
	type Err = Infallible;

	fn from_str(s: &str) -> Result<Self, Self::Err> {
		Ok(match s {
			"plain" => Self::Plain,
			"env" => Self::Env,
			_ => unreachable!("bad format"),
		})
	}
}

fn render_plain(field: Field, with: With) {
	let name = field.name.join(".");

	let mut extra = Vec::with_capacity(3);

	if with.types {
		extra.push(format!("{{{}}}", field.typename));
	}

	if with.raws {
		extra.push(format!(
			"[{}]",
			field
				.raw
				.into_iter()
				.map(|x| format!("{:02x}", x))
				.collect::<Vec<String>>()
				.join(" "),
		));
	}

	if with.defs {
		extra.push(field.def.to_string());
	}

	println!("{}:\t{}\t{}", name, field.value, extra.join("\t"));
}

fn render_env(field: Field, with: With) {
	let name = field.name.join("_");
	println!("{}='{}'", name, field.value);

	if with.types {
		println!("{}__TYPE='{}'", name, field.typename);
	}

	if with.defs {
		println!("{}__DEF='{}'", name, field.def);
	}

	if with.raws {
		println!(
			"{}__RAW='{}'",
			name,
			field
				.raw
				.into_iter()
				.map(|x| format!("{:02x}", x))
				.collect::<String>()
		);
	}
}
