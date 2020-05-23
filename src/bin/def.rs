use clap::{App, AppSettings, Arg};
use defnew::{
	def::{self, layout::Layable, Def},
	parse_def, platform,
};
use eyre::{eyre, WrapErr};
use lexpr::Value;
use std::str::FromStr;
use thiserror::Error;

fn main() -> color_eyre::Result<()> {
	let pointer_width_default = platform::native::POINTER_WIDTH.to_string();
	let endianness = Arg::new("endian")
		.long("endian")
		.takes_value(true)
		.possible_values(&["little", "big", "native"])
		.about("Specifies endianness");

	let author = format!("CC BY-SA-NC 4.0 - {}", env!("CARGO_PKG_HOMEPAGE"));
	let mut app = App::new("defnew")
		.author(author.as_str())
		.about("def: constructs, normalises, and lays out defs")
		.version(clap::crate_version!())
		.setting(AppSettings::AllowExternalSubcommands)
		.after_help("There are also type aliases: {i,u}{8,16,32,64,128}, f{32,64}, and {i,u}size (depending on platform).")
		.arg(
			Arg::new("show-layout")
				.short('L')
				.long("show-layout")
				.about("Prints layout to stderr"),
		)
		.subcommand(
			App::new("bool")
				.about("Makes a boolean def")
				.arg(
					Arg::new("width")
						.takes_value(true)
						.default_value("1")
						.value_name("bytes")
						.about("Specifies boolean width"),
				),
		)
		.subcommand(
			App::new("int")
				.about("Makes a signed integral def")
				.arg(endianness.clone())
				.arg(
					Arg::new("width")
						.takes_value(true)
						.value_name("bytes")
						.required(true)
						.about("Integral width"),
				),
		)
		.subcommand(
			App::new("uint")
				.about("Makes an unsigned integral def")
				.arg(endianness.clone())
				.arg(
					Arg::new("width")
						.takes_value(true)
						.value_name("bytes")
						.required(true)
						.about("Integral width"),
				),
		)
		.subcommand(
			App::new("float")
				.about("Makes a floating point def")
				.arg(endianness.clone())
				.arg(
					Arg::new("min align")
						.long("align")
						.takes_value(true)
						.about("Specifies float alignment"),
				)
				.arg(
					Arg::new("format")
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
						.about("Float format"),
				),
		)
		.subcommand(
			App::new("struct")
				.about("Makes a struct def")
				.arg(
					Arg::new("name")
						.long("name")
						.takes_value(true)
						.about("Names the struct"),
				)
				.arg(
					Arg::new("align")
						.long("align")
						.takes_value(true)
						.value_name("min align")
						.about("Raises struct alignment"),
				)
				.arg(
					Arg::new("packed")
						.long("packed")
						.takes_value(true)
						.value_name("max align")
                		.require_equals(true)
						.about("Lowers struct alignment"),
				)
				.arg(
					Arg::new("types")
						.takes_value(true)
						.value_name("[name:]type")
						.multiple(true)
						.about("Fields (zero or more)"),
				),
		)
		.subcommand(
			App::new("enum")
				.about("Makes an enum def")
				.arg(
					Arg::new("name")
						.long("name")
						.takes_value(true)
						.about("Names the enum"),
				)
				.arg(
					Arg::new("width")
						.long("width")
						.takes_value(true)
						.about("Raises enum width"),
				)
				.arg(endianness.clone())
				.arg(
					Arg::new("variants")
						.takes_value(true)
						.value_name("name[:discriminant]")
						.multiple(true)
						.required(true)
						.min_values(1)
						.about("Variants (one or more)"),
				),
		)
		.subcommand(
			App::new("union")
				.about("Makes a union def")
				.arg(
					Arg::new("name")
						.long("name")
						.takes_value(true)
						.about("Names the union"),
				)
				.arg(
					Arg::new("align")
						.long("align")
						.takes_value(true)
						.about("Raises union alignment"),
				)
				.arg(
					Arg::new("alterns")
						.takes_value(true)
						.value_name("name:type")
						.multiple(true)
						.required(true)
						.min_values(1)
						.about("Alternates (one or more)"),
				),
		)
		.subcommand(
			App::new("array")
				.about("Makes an array def")
				.arg(
					Arg::new("name")
						.long("name")
						.takes_value(true)
						.about("Names the array"),
				)
				.arg(
					Arg::new("stride")
						.long("stride")
						.takes_value(true)
						.about("Specifies array stride"),
				)
				.arg(
					Arg::new("length")
						.takes_value(true)
						.required(true)
						.about("Array length (zero for unspecified)"),
				)
				.arg(
					Arg::new("type")
						.takes_value(true)
						.required(true)
						.about("Array element type"),
				),
		)
		.subcommand(
			App::new("opaque")
				.about("Makes an opaque def (low-level)")
		)
		.subcommand(
			App::new("pointer")
				.about("Makes a raw pointer def (low-level)")
				.arg(endianness.clone())
				.arg(
					Arg::new("width")
						.long("width")
						.takes_value(true)
						.default_value(&pointer_width_default)
						.about("Specifies pointer width"),
				)
				.arg(
					Arg::new("mutable")
						.about("Whether pointer is mutable"),
				)
				.arg(
					Arg::new("points-to")
						.long("points-to")
						.takes_value(true)
						.value_name("def")
						.about("Specifies what type is behind the pointer"),
				)
				.arg(
					Arg::new("context")
						.takes_value(true)
						.possible_values(&["local", "remote"])
						.required(true)
						.about("Pointer context (if it's pointing out or within the def)"),
				)
				.arg(
					Arg::new("value")
						.takes_value(true)
						.required(true)
						.about("Pointer value (decimal)"),
				),
		)
		.subcommand(
			App::new("padding")
				.about("Makes a padding def (low-level)")
				.arg(
					Arg::new("bits")
						.takes_value(true)
						.required(true)
						.about("Length of the padding"),
				),
		)
		.subcommand(
			App::new("parse")
				.about("Parses an s-expression of any arbitrary def")
				.arg(
					Arg::new("def")
						.takes_value(true)
						.value_name("s-exp")
						.required(true)
						.about("Arbitrary def"),
				),
		);

	let mut help = Vec::new();
	app.write_help(&mut help).map_err(ClapError)?;
	let help = String::from_utf8(help)?;

	let args = app.get_matches();

	let def = match args.subcommand() {
		("bool", Some(subargs)) => make_bool(subargs),
		("int", Some(subargs)) => make_integral(subargs, true),
		("uint", Some(subargs)) => make_integral(subargs, false),
		("float", Some(subargs)) => make_float(subargs),

		("struct", Some(subargs)) => make_struct(subargs),
		("enum", Some(subargs)) => make_enum(subargs),
		("union", Some(subargs)) => make_union(subargs),
		("array", Some(subargs)) => make_array(subargs),

		("opaque", _) => Ok(Def::Opaque),
		("pointer", Some(subargs)) => make_pointer(subargs),
		("padding", Some(subargs)) => make_padding(subargs),

		("parse", Some(subargs)) => {
			let typestr: String = subargs.value_of_t("def").map_err(ClapError)?;
			parse_def(&typestr).map_err(|e| e.into())
		}

		(alias, _) => {
			if let Some(def) = platform::parse_native_type(alias) {
				Ok(def)
			} else {
				eprintln!("{}", help);
				Err(NoCommandProvided).wrap_err_with(|| format!("no such command: {}", alias))
			}
		}
	}?;

	if args.is_present("show-layout") {
		eprintln!("{}", def.layout());
	}

	println!("{}", Value::from(def));
	Ok(())
}

#[derive(Debug, Error)]
#[error("unrecognised type or type alias")]
struct NoCommandProvided;

#[derive(Debug, Error)]
#[error("argument error: {0}")]
struct ClapError(clap::Error);

fn make_bool(args: &clap::ArgMatches) -> color_eyre::Result<Def> {
	use def::{Boolean, ByteWidth};
	let width: ByteWidth = args.value_of_t("width").map_err(ClapError)?;

	Ok(Def::Boolean(Boolean { width }))
}

fn make_integral(args: &clap::ArgMatches, signed: bool) -> color_eyre::Result<Def> {
	use def::Integral;
	let width = args.value_of_t("width").map_err(ClapError)?;
	let endian = args
		.value_of_t("endian")
		.map(Some)
		.unwrap_or_else(exit_unless_none)
		.unwrap_or(platform::native::ENDIAN);

	Ok(Def::Integral(Integral {
		signed,
		endian,
		width,
	}))
}

fn make_float(args: &clap::ArgMatches) -> color_eyre::Result<Def> {
	use def::float::Float;

	let format = args.value_of_t("format").map_err(ClapError)?;
	let endian = args
		.value_of_t("endian")
		.map(Some)
		.unwrap_or_else(exit_unless_none)
		.unwrap_or(platform::native::ENDIAN);
	let align = args
		.value_of_t("align")
		.map(Some)
		.unwrap_or_else(exit_unless_none);

	Ok(Def::Float(Float {
		format,
		endian,
		align,
	}))
}

fn make_struct(args: &clap::ArgMatches) -> color_eyre::Result<Def> {
	use def::r#struct::{Field, Struct};
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

	Ok(Def::Struct(Struct {
		name: args.value_of_t("name").ok(),
		align: args
			.value_of_t("align")
			.map(Some)
			.unwrap_or_else(exit_unless_none),
		packed: args
			.value_of_t("packed")
			.map(Some)
			.unwrap_or_else(exit_unless_none),
		fields,
	}))
}

fn make_enum(args: &clap::ArgMatches) -> color_eyre::Result<Def> {
	use def::r#enum::{Enum, Variant};

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
			value = d.parse().wrap_err("discriminant must be a number")?;
		}

		variants.push(Variant {
			name: name.into(),
			value,
		});
		value += 1;
	}

	Ok(Def::Enum(Enum {
		name: args.value_of_t("name").ok(),
		width: args
			.value_of_t("width")
			.map(Some)
			.unwrap_or_else(exit_unless_none),
		endian: args
			.value_of_t("endian")
			.map(Some)
			.unwrap_or_else(exit_unless_none)
			.unwrap_or(platform::native::ENDIAN),
		variants,
	}))
}

fn make_union(args: &clap::ArgMatches) -> color_eyre::Result<Def> {
	use def::r#union::{Altern, Union};

	let alts = args.values_of("alterns").unwrap_or_default();

	let mut alterns = Vec::with_capacity(alts.len());
	for arg in alts {
		let parts: Vec<&str> = arg.splitn(2, ":").collect();
		let (name, typestr) = match *parts {
			[name, typestr] => (name, typestr),
			_ => Err(eyre!("alternate format must be name:type"))?,
		};

		alterns.push(Altern {
			name: name.into(),
			def: parse_def(typestr)?,
		});
	}

	Ok(Def::Union(Union {
		name: args.value_of_t("name").ok(),
		align: args
			.value_of_t("align")
			.map(Some)
			.unwrap_or_else(exit_unless_none),
		alterns,
	}))
}

fn make_array(args: &clap::ArgMatches) -> color_eyre::Result<Def> {
	use def::Array;
	use std::num::NonZeroU64;

	let typestr: String = args.value_of_t("type").map_err(ClapError)?;

	Ok(Def::Array(Array {
		name: args.value_of_t("name").ok(),
		stride: args
			.value_of_t("stride")
			.map(Some)
			.unwrap_or_else(exit_unless_none),
		length: NonZeroU64::new(args.value_of_t("length").map_err(ClapError)?),
		def: Box::new(parse_def(&typestr)?),
	}))
}

fn make_pointer(args: &clap::ArgMatches) -> color_eyre::Result<Def> {
	use def::pointer::Pointer;

	let width = args.value_of_t("width").map_err(ClapError)?;
	let endian = args
		.value_of_t("endian")
		.map(Some)
		.unwrap_or_else(exit_unless_none)
		.unwrap_or(platform::native::ENDIAN);

	let context = args.value_of_t("context").map_err(ClapError)?;
	let value = args.value_of_t("value").map_err(ClapError)?;
	let mutable = args.is_present("mutable");

	let def = if let Some(typestr) = args.value_of("points-to") {
		Some(Box::new(parse_def(typestr)?))
	} else {
		None
	};

	Ok(Def::Pointer(Pointer {
		width,
		endian,
		context,
		mutable,
		value,
		def,
	}))
}

fn make_padding(args: &clap::ArgMatches) -> color_eyre::Result<Def> {
	let bits = args.value_of_t("bits").map_err(ClapError)?;
	Ok(Def::Padding(bits))
}

// TODO: improve this to return 1/ the argument name, 2/ the FromStr error message
fn exit_unless_none<T>(e: clap::Error) -> Option<T> {
	if let clap::ErrorKind::ArgumentNotFound = e.kind {
		None
	} else {
		panic!("{}", e)
	}
}
