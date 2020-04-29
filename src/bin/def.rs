#[macro_use]
extern crate clap;

use clap::{App, AppSettings, Arg, SubCommand};
use defnew::{
	def::{self, layout::Layable, Def},
	parse_def, platform,
};
use lexpr::Value;
use std::str::FromStr;
use thiserror::Error;

fn main() -> Result<(), Box<dyn std::error::Error>> {
	let pointer_width_default = platform::native::POINTER_WIDTH.to_string();
	let endianness = Arg::with_name("endian")
		.long("endian")
		.takes_value(true)
		.possible_values(&["little", "big", "native"])
		.help("Specifies endianness");

	let args = App::new("defnew")
		.author(&*format!("CC BY-SA-NC 4.0 - {}", env!("CARGO_PKG_HOMEPAGE")))
		.about("def: constructs, normalises, and lays out defs")
		.version(clap::crate_version!())
		.setting(AppSettings::AllowExternalSubcommands)
		.after_help("There are also type aliases: {i,u}{8,16,32,64,128}, f{32,64}, and {i,u}size (depending on platform).")
		.arg(
			Arg::with_name("show-layout")
				.short("L")
				.long("show-layout")
				.help("Prints layout to stderr"),
		)
		.subcommand(
			SubCommand::with_name("bool")
				.about("Makes a boolean def")
				.arg(
					Arg::with_name("width")
						.takes_value(true)
						.default_value("1")
						.value_name("bytes")
						.help("Specifies boolean width"),
				),
		)
		.subcommand(
			SubCommand::with_name("int")
				.about("Makes a signed integral def")
				.arg(endianness.clone())
				.arg(
					Arg::with_name("width")
						.takes_value(true)
						.value_name("bytes")
						.required(true)
						.help("Integral width"),
				),
		)
		.subcommand(
			SubCommand::with_name("uint")
				.about("Makes an unsigned integral def")
				.arg(endianness.clone())
				.arg(
					Arg::with_name("width")
						.takes_value(true)
						.value_name("bytes")
						.required(true)
						.help("Integral width"),
				),
		)
		.subcommand(
			SubCommand::with_name("float")
				.about("Makes a floating point def")
				.arg(endianness.clone())
				.arg(
					Arg::with_name("min align")
						.long("align")
						.takes_value(true)
						.help("Specifies float alignment"),
				)
				.arg(
					Arg::with_name("format")
						.takes_value(true)
						.possible_values(&[
							"binary-16",
							"binary-32",
							"binary-64",
							"binary-128",
							"binary-256",
							"decimal-32",
							"decimal-64",
							"decimal-128",
						])
						.required(true)
						.help("Float format"),
				),
		)
		.subcommand(
			SubCommand::with_name("struct")
				.about("Makes a struct def")
				.arg(
					Arg::with_name("name")
						.long("name")
						.takes_value(true)
						.help("Names the struct"),
				)
				.arg(
					Arg::with_name("align")
						.long("align")
						.takes_value(true)
						.value_name("min align")
						.help("Raises struct alignment"),
				)
				.arg(
					Arg::with_name("packed")
						.long("packed")
						.takes_value(true)
						.value_name("max align")
						.help("Lowers struct alignment"),
				)
				.arg(
					Arg::with_name("types")
						.takes_value(true)
						.value_name("[name:]type")
						.multiple(true)
						.help("Fields (zero or more)"),
				),
		)
		.subcommand(
			SubCommand::with_name("enum")
				.about("Makes an enum def")
				.arg(
					Arg::with_name("name")
						.long("name")
						.takes_value(true)
						.help("Names the enum"),
				)
				.arg(
					Arg::with_name("width")
						.long("width")
						.takes_value(true)
						.help("Raises enum width"),
				)
				.arg(endianness.clone())
				.arg(
					Arg::with_name("variants")
						.takes_value(true)
						.value_name("name[:discriminant]")
						.multiple(true)
						.required(true)
						.min_values(1)
						.help("Variants (one or more)"),
				),
		)
		.subcommand(
			SubCommand::with_name("union")
				.about("Makes a union def")
				.arg(
					Arg::with_name("name")
						.long("name")
						.takes_value(true)
						.help("Names the union"),
				)
				.arg(
					Arg::with_name("align")
						.long("align")
						.takes_value(true)
						.help("Raises union alignment"),
				)
				.arg(
					Arg::with_name("alterns")
						.takes_value(true)
						.value_name("name:type")
						.multiple(true)
						.required(true)
						.min_values(1)
						.help("Alternates (one or more)"),
				),
		)
		.subcommand(
			SubCommand::with_name("array")
				.about("Makes an array def")
				.arg(
					Arg::with_name("name")
						.long("name")
						.takes_value(true)
						.help("Names the array"),
				)
				.arg(
					Arg::with_name("stride")
						.long("stride")
						.takes_value(true)
						.help("Specifies array stride"),
				)
				.arg(
					Arg::with_name("length")
						.takes_value(true)
						.required(true)
						.help("Array length"),
				)
				.arg(
					Arg::with_name("type")
						.takes_value(true)
						.required(true)
						.help("Array element type"),
				),
		)
		.subcommand(
			SubCommand::with_name("opaque")
				.about("Makes an opaque def (low-level)")
		)
		.subcommand(
			SubCommand::with_name("pointer")
				.about("Makes a raw pointer def (low-level)")
				.arg(endianness.clone())
				.arg(
					Arg::with_name("width")
						.long("width")
						.takes_value(true)
						.default_value(&pointer_width_default)
						.help("Specifies pointer width"),
				)
				.arg(
					Arg::with_name("mutable")
						.help("Whether pointer is mutable"),
				)
				.arg(
					Arg::with_name("points-to")
						.long("points-to")
						.takes_value(true)
						.value_name("def")
						.help("Specifies what type is behind the pointer"),
				)
				.arg(
					Arg::with_name("context")
						.takes_value(true)
						.possible_values(&["local", "remote"])
						.required(true)
						.help("Pointer context (if it's pointing out or within the def)"),
				)
				.arg(
					Arg::with_name("value")
						.takes_value(true)
						.required(true)
						.help("Pointer value (decimal)"),
				),
		)
		.subcommand(
			SubCommand::with_name("padding")
				.about("Makes a padding def (low-level)")
				.arg(
					Arg::with_name("bits")
						.takes_value(true)
						.required(true)
						.help("Length of the padding"),
				),
		)
		.subcommand(
			SubCommand::with_name("parse")
				.about("Parses an s-expression of any arbitrary def")
				.arg(
					Arg::with_name("def")
						.takes_value(true)
						.value_name("s-exp")
						.required(true)
						.help("Arbitrary def"),
				),
		)
		.get_matches();

	let def = match args.subcommand() {
		("bool", Some(subargs)) => make_bool(subargs),
		("int", Some(subargs)) => make_integral(subargs, true),
		("uint", Some(subargs)) => make_integral(subargs, false),
		("float", Some(subargs)) => make_float(subargs),

		("struct", Some(subargs)) => make_struct(subargs),
		("enum", Some(subargs)) => make_enum(subargs),
		("union", Some(subargs)) => make_union(subargs),
		("array", Some(subargs)) => make_array(subargs),

		("opaque", _) => Def::Opaque,
		("pointer", Some(subargs)) => make_pointer(subargs),
		("padding", Some(subargs)) => make_padding(subargs),

		("parse", Some(subargs)) => {
			let typestr = value_t!(subargs, "def", String).unwrap_or_else(|e| e.exit());

			parse_def(&typestr).unwrap_or_else(|err| {
				clap::Error::with_description(&err.to_string(), clap::ErrorKind::InvalidValue)
					.exit()
			})
		}

		(alias, _) => {
			if let Some(def) = platform::parse_native_type(alias) {
				def
			} else {
				eprintln!("{}", args.usage());
				return Err(NoCommandProvided)?;
			}
		}
	};

	if args.is_present("show-layout") {
		eprintln!("{}", def.layout());
	}

	println!("{}", Value::from(def));
	Ok(())
}

#[derive(Debug, Error)]
#[error("unrecognised type or type alias")]
struct NoCommandProvided;

fn make_bool(args: &clap::ArgMatches<'_>) -> Def {
	use def::{Boolean, ByteWidth};
	let width = value_t!(args, "width", ByteWidth).unwrap_or_else(|e| e.exit());

	Def::Boolean(Boolean { width })
}

fn make_integral(args: &clap::ArgMatches<'_>, signed: bool) -> Def {
	use def::{ByteWidth, Endianness, Integral};
	let width = value_t!(args, "width", ByteWidth).unwrap_or_else(|e| e.exit());
	let endian = value_t!(args, "endian", Endianness)
		.map(Some)
		.unwrap_or_else(exit_unless_none)
		.unwrap_or(platform::native::ENDIAN);

	Def::Integral(Integral {
		signed,
		endian,
		width,
	})
}

fn make_float(args: &clap::ArgMatches<'_>) -> Def {
	use def::{
		float::{Float, Format},
		Alignment, Endianness,
	};

	let format = value_t!(args, "format", Format).unwrap_or_else(|e| e.exit());
	let endian = value_t!(args, "endian", Endianness)
		.map(Some)
		.unwrap_or_else(exit_unless_none)
		.unwrap_or(platform::native::ENDIAN);
	let align = value_t!(args, "align", Alignment)
		.map(Some)
		.unwrap_or_else(exit_unless_none);

	Def::Float(Float {
		format,
		endian,
		align,
	})
}

fn make_struct(args: &clap::ArgMatches<'_>) -> Def {
	use def::{
		r#struct::{Field, Struct},
		Alignment,
	};
	let types = args.values_of("types").unwrap_or_default();
	let mut fields = Vec::with_capacity(types.len());

	for arg in types {
		let parts: Vec<&str> = arg.splitn(2, ":").collect();
		let (name, typestr) = match *parts {
			[typestr] => (None, typestr),
			[name, typestr] => (Some(name), typestr),
			_ => unreachable!(),
		};

		let def = if let Some(def) = platform::parse_native_type(typestr) {
			def
		} else if let Ok(def) = Def::from_str(typestr) {
			def
		} else if let Some(name) = name {
			Def::from_str(&(name.to_string() + ":" + typestr)).unwrap()
		} else {
			// TODO: better error
			panic!("invalid definition");
		};

		fields.push(if let Some(name) = name {
			Field::named(name, def)
		} else {
			Field::anonymous(def)
		});
	}

	Def::Struct(Struct {
		name: value_t!(args, "name", String).ok(),
		align: value_t!(args, "align", Alignment)
			.map(Some)
			.unwrap_or_else(exit_unless_none),
		packed: value_t!(args, "packed", Alignment)
			.map(Some)
			.unwrap_or_else(exit_unless_none),
		fields,
	})
}

fn make_enum(args: &clap::ArgMatches<'_>) -> Def {
	use def::{
		r#enum::{Enum, Variant},
		ByteWidth, Endianness,
	};

	let vars = args.values_of("variants").unwrap_or_default();

	let mut variants = Vec::with_capacity(vars.len());
	let mut value = 0;
	for arg in vars {
		let parts: Vec<&str> = arg.splitn(2, ":").collect();
		let (name, disc) = match *parts {
			[name] => (name, None),
			[name, disc] => (name, Some(disc)),
			_ => unreachable!(),
		};

		if let Some(d) = disc {
			value = d.parse().unwrap_or_else(|_| {
				clap::Error::with_description(
					"discriminant must be a number",
					clap::ErrorKind::InvalidValue,
				)
				.exit()
			});
		}

		variants.push(Variant {
			name: name.into(),
			value,
		});
		value += 1;
	}

	Def::Enum(Enum {
		name: value_t!(args, "name", String).ok(),
		width: value_t!(args, "width", ByteWidth)
			.map(Some)
			.unwrap_or_else(exit_unless_none),
		endian: value_t!(args, "endian", Endianness)
			.map(Some)
			.unwrap_or_else(exit_unless_none)
			.unwrap_or(platform::native::ENDIAN),
		variants,
	})
}

fn make_union(args: &clap::ArgMatches<'_>) -> Def {
	use def::{
		r#union::{Altern, Union},
		Alignment,
	};

	let alts = args.values_of("alterns").unwrap_or_default();

	let mut alterns = Vec::with_capacity(alts.len());
	for arg in alts {
		let parts: Vec<&str> = arg.splitn(2, ":").collect();
		let (name, typestr) = match *parts {
			[name, typestr] => (name, typestr),
			_ => clap::Error::with_description(
				"alternate format must be name:type",
				clap::ErrorKind::InvalidValue,
			)
			.exit(),
		};

		alterns.push(Altern {
			name: name.into(),
			def: parse_def(typestr).unwrap_or_else(|err| {
				clap::Error::with_description(&err.to_string(), clap::ErrorKind::InvalidValue)
					.exit()
			}),
		});
	}

	Def::Union(Union {
		name: value_t!(args, "name", String).ok(),
		align: value_t!(args, "align", Alignment)
			.map(Some)
			.unwrap_or_else(exit_unless_none),
		alterns,
	})
}

fn make_array(args: &clap::ArgMatches<'_>) -> Def {
	use def::Array;
	use std::num::NonZeroU64;

	let typestr = value_t!(args, "type", String).unwrap_or_else(|e| e.exit());

	Def::Array(Array {
		name: value_t!(args, "name", String).ok(),
		stride: value_t!(args, "stride", NonZeroU64)
			.map(Some)
			.unwrap_or_else(exit_unless_none),
		length: value_t!(args, "length", NonZeroU64).unwrap_or_else(|e| e.exit()),
		def: Box::new(parse_def(&typestr).unwrap_or_else(|err| {
			clap::Error::with_description(&err.to_string(), clap::ErrorKind::InvalidValue).exit()
		})),
	})
}

fn make_pointer(args: &clap::ArgMatches<'_>) -> Def {
	use def::{
		pointer::{Context, Pointer},
		ByteWidth, Endianness,
	};

	let width = value_t!(args, "width", ByteWidth).unwrap_or_else(|e| e.exit());
	let endian = value_t!(args, "endian", Endianness)
		.map(Some)
		.unwrap_or_else(exit_unless_none)
		.unwrap_or(platform::native::ENDIAN);

	let context = value_t!(args, "context", Context).unwrap_or_else(|e| e.exit());
	let value = value_t!(args, "value", u64).unwrap_or_else(|e| e.exit());
	let mutable = args.is_present("mutable");

	let def = if let Some(typestr) = args.value_of("points-to") {
		Some(Box::new(parse_def(typestr).unwrap_or_else(|err| {
			clap::Error::with_description(&err.to_string(), clap::ErrorKind::InvalidValue).exit()
		})))
	} else {
		None
	};

	Def::Pointer(Pointer {
		width,
		endian,
		context,
		mutable,
		value,
		def,
	})
}

fn make_padding(args: &clap::ArgMatches<'_>) -> Def {
	use std::num::NonZeroU64;
	let bits = value_t!(args, "bits", NonZeroU64).unwrap_or_else(|e| e.exit());
	Def::Padding(bits)
}

// TODO: improve this to return 1/ the argument name, 2/ the FromStr error message
fn exit_unless_none<T>(e: clap::Error) -> Option<T> {
	if let clap::ErrorKind::ArgumentNotFound = e.kind {
		None
	} else {
		e.exit()
	}
}
