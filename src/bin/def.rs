use defnew as lib;
use lexpr::Value;
use structopt::StructOpt;

/// def constructs normalised s-exp defs from arguments
#[derive(Debug, StructOpt)]
struct Args {
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
	let args = Args::from_args();

	let mut fields = Vec::with_capacity(args.raw.len());

	for arg in args.raw {
		let parts: Vec<&str> = arg.splitn(2, ":").collect();
		let (name, typestr) = match *parts {
			[typestr] => (None, typestr),
			[name, typestr] => (Some(name), typestr),
			_ => unreachable!(),
		};

		let def = lib::platform::parse_native_type(typestr)
			.or_else(|| todo!("parse from s-exp"))
			.unwrap();

		fields.push(if let Some(name) = name {
			lib::def::r#struct::Field::named(name, def)
		} else {
			lib::def::r#struct::Field::anonymous(def)
		});
	}

	let def = lib::Def::Struct(lib::def::Struct {
		name: args.name,
		align: args.align,
		packed: args.packed,
		fields,
	});

	use lib::def::layout::Layable;
	let layout = def.layout();

	println!("{}", layout);
	println!("{}", Value::from(def));

	Ok(())
}
