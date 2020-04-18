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
	dbg!(&args);

	let def = lib::Def::Struct(lib::def::Struct {
		name: args.name,
		align: args.align,
		packed: args.packed,
		fields: vec![
			lib::def::r#struct::Field::anonymous(lib::def::Boolean {
				width: std::num::NonZeroU8::new(2).unwrap(),
				true_pattern: None,
				false_pattern: None,
			}),
			lib::def::r#struct::Field::anonymous(lib::def::Array::anonymous(
				lib::def::Boolean::default().into(),
				unsafe { std::num::NonZeroU64::new_unchecked(3) },
			)),
		],
	});

	dbg!(&def);

	use lib::def::layout::Layable;
	let layout = def.layout();
	dbg!(&layout);
	use lib::def::alignment::Alignable;
	dbg!(&def.align());

	#[repr(C, packed(1))]
	struct Example {
		a: u16,
		b: [u8; 3],
	}

	dbg!(std::mem::size_of::<Example>());
	dbg!(std::mem::align_of::<Example>());

	let example = Example {
		a: 0b1111_1111_1111_1111,
		b: [0xAA, 0xBB, 0xCC],
	};

	let example_bytes: [u8; std::mem::size_of::<Example>()] =
		unsafe { std::mem::transmute(example) };
	println!("{:x?}", example_bytes);

	println!("layout:\n{}", layout);
	println!("{}", Value::from(def));

	Ok(())
}
