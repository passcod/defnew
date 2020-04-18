use clap::{App, AppSettings, Arg, SubCommand};
use defnew::{
	self as lib,
	def::{
		layout::Layable,
		r#struct::{self, Struct},
		Def,
	},
};
use lexpr::Value;
use std::str::FromStr;
use structopt::StructOpt;

/// def constructs normalised s-exp defs from arguments
#[derive(Debug, StructOpt)]
struct Args {
	/// Print the layout to stderr
	#[structopt(long = "show-layout")]
	show_layout: bool,

	/// Name the outer structure
	#[structopt(long)]
	name: Option<String>,

	/// Raise structure alignment
	#[structopt(long, name = "min align")]
	align: Option<lib::def::Alignment>,

	/// Lower structure alignment
	// FIXME: use default_missing_value=1 when clap#1587 lands
	#[structopt(long, name = "max align")]
	packed: Option<lib::def::Alignment>,

	#[structopt(name = "TYPES")]
	raw: Vec<String>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
	let pointer_width_default = lib::platform::native::POINTER_WIDTH.to_string();
	let endianness = Arg::with_name("endian")
		.long("endian")
		.takes_value(true)
		.possible_values(&["little", "big", "native"])
		.help("Specifies endianness");

	let app = App::new("defnew")
		.author(clap::crate_authors!())
		.about("def: generate, normalise, and layout defs")
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
						.long("width")
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
					Arg::with_name("min align")
						.long("align")
						.takes_value(true)
						.help("Raises struct alignment"),
				)
				.arg(
					Arg::with_name("max align")
						.long("packed")
						.takes_value(true)
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
			SubCommand::with_name("pointer")
				.about("Makes a pointer def (low-level)")
				.arg(endianness.clone())
				.arg(
					Arg::with_name("width")
						.long("width")
						.takes_value(true)
						.default_value(&pointer_width_default)
						.help("Specifies pointer width"),
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
						.help("Pointer value (hex with 0x, binary with 0b)"),
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

	dbg!(app);

	let mut args = Args::from_args();

	// TODO: subcommands instead of this mess
	let def = match args.raw.remove(0).as_str() {
		"struct" => args_as_struct(&args),
		otherwise => {
			args.raw.insert(0, otherwise.into());
			args_as_struct(&args)
		}
	};

	if args.show_layout {
		eprintln!("{}", def.layout());
	}

	println!("{}", Value::from(def));
	Ok(())
}

fn args_as_struct(args: &Args) -> Def {
	let mut fields = Vec::with_capacity(args.raw.len());

	for arg in &args.raw {
		let parts: Vec<&str> = arg.splitn(2, ":").collect();
		let (name, typestr) = match *parts {
			[typestr] => (None, typestr),
			[name, typestr] => (Some(name), typestr),
			_ => unreachable!(),
		};

		let def = if let Some(def) = lib::platform::parse_native_type(typestr) {
			def
		} else if let Ok(def) = Def::from_str(typestr) {
			def
		} else if let Some(name) = name {
			Def::from_str(&(name.to_string() + ":" + typestr)).unwrap()
		} else {
			panic!("invalid definition");
		};

		fields.push(if let Some(name) = name {
			r#struct::Field::named(name, def)
		} else {
			r#struct::Field::anonymous(def)
		});
	}

	Def::Struct(Struct {
		name: args.name.clone(),
		align: args.align,
		packed: args.packed,
		fields,
	})
}
