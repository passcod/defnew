use defnew::{parse_def, Def};
use html5ever::tendril::stream::TendrilSink;
use kuchiki::{parse_html, NodeRef};
use std::{
	collections::HashMap,
	fs::{read_dir, File},
	io::{self, Write},
	path::{Path, PathBuf},
	process::Command,
};
use syn::{Attribute, Type};
use thiserror::Error;

#[derive(Debug, Error)]
enum Error {
	#[error("{0}")]
	About(#[from] About),

	#[error("command failed: {0}")]
	CommandFailed(&'static str),

	#[error("css selector not matching")]
	NoMatch,

	#[error("missing typedef")]
	MissingType,

	#[error("missing type kind in filename")]
	MissingTypekind,

	#[error("missing type name in filename")]
	MissingTypename,

	#[error("typedef isn't supported ({0}): {1}")]
	UnsupportedType(&'static str, String),

	#[error("io is not happy")]
	Io(#[from] io::Error),

	#[error("syn is not happy")]
	Syn(#[from] syn::Error),

	#[error("literal doesn't parse to usize")]
	LiteralNotUsize(syn::Error),

	#[error("could not resolve {left} defs out of {total}")]
	UnresolvedDefs { total: usize, left: usize },
}

#[allow(dead_code)]
#[derive(Debug, Error)]
enum About {
	#[error("about a file: {path}")]
	File {
		#[source]
		err: Box<dyn std::error::Error + Sync + Send>,
		path: PathBuf,
	},
}

impl About {
	pub fn a_file(
		path: impl Into<PathBuf>,
		err: impl std::error::Error + Sync + Send + 'static,
	) -> Self {
		Self::File {
			err: Box::new(err),
			path: path.into(),
		}
	}
}

#[rustfmt::skip]
const IGNORED_TYPES: [&'static str; 14] = [
	// unprintable consts
	"SEM_FAILED",   // sem_t
	"RTLD_DEFAULT", // *mut c_void
	"RTLD_NEXT",    // *mut c_void
	"MAP_FAILED",   // *mut c_void

	// initialiser consts
	"PTHREAD_RWLOCK_INITIALIZER",
	"PTHREAD_COND_INITIALIZER",
	"PTHREAD_MUTEX_INITIALIZER",
	"PTHREAD_ADAPTIVE_MUTEX_INITIALIZER_NP",
	"PTHREAD_ERRORCHECK_MUTEX_INITIALIZER_NP",
	"PTHREAD_RECURSIVE_MUTEX_INITIALIZER_NP",

	// structs
	"sigaction",  // contains an extern "C" fn()
	"ucontext_t", // recursive
	"addrinfo",   // recursive
	"ifaddrs",    // recursive
];

fn main() -> color_eyre::Result<()> {
	if !Command::new("cargo")
		.arg("doc")
		.arg("-p")
		.arg("libc")
		.status()?
		.success()
	{
		return Err(Error::CommandFailed("cargo doc"))?;
	}

	let mut consts = Vec::new();
	let mut types = TypeMap::new();

	'readdir: for entry in read_dir("target/doc/libc")? {
		let entry = entry.map_err(|err| About::a_file("target/doc/libc", err))?;

		if !entry.file_type()?.is_file() {
			continue;
		}

		let name = match entry.file_name().to_str() {
			Some(s) => s.to_string(),
			None => continue,
		};

		let (kind, tyname) = {
			let mut split = name.split(".");
			(
				split
					.next()
					.ok_or(About::a_file(&name, Error::MissingTypekind))?,
				split
					.next()
					.ok_or(About::a_file(&name, Error::MissingTypename))?,
			)
		};

		for ignored in &IGNORED_TYPES {
			if &tyname == ignored {
				continue 'readdir;
			}
		}

		match kind {
			"constant" => {
				consts.push(tyname.to_string());
			}
			"type" => {
				types.insert(MaybeType::from_type_file(entry.path())?);
			}
			"enum" => {
				types.insert(MaybeType::from_enum_file(entry.path())?);
			}
			"struct" => {
				types.insert(MaybeType::from_struct_file(entry.path())?);
			}
			_ => {}
		}

		print!(".");
	}

	// libc-const
	{
		println!("obtained {} consts", consts.len());

		let libc_const_file = File::create("src/bin/libc-const.rs")?;
		writeln!(
			&libc_const_file,
			r#"
			#[rustfmt::skip]
			#[allow(deprecated)]
			fn main() {{
				let args = clap::App::new("defnew")
					.author(&*format!(
						"CC BY-SA-NC 4.0 - {{}}",
						env!("CARGO_PKG_HOMEPAGE")
					))
					.about("libc-const: provides values for libc constants")
					.after_help("Values are hard-coded at compile and are not guaranteed to be correct for your system.")
					.version(clap::crate_version!())
					.setting(clap::AppSettings::SubcommandRequired)
			"#
		)?;

		for constant in &consts {
			writeln!(
				&libc_const_file,
				r#".subcommand(clap::SubCommand::with_name("{}"))"#,
				constant
			)?;
		}

		writeln!(
			&libc_const_file,
			r#"
			.get_matches();

			println!("{{}}", match args.subcommand_name().unwrap() {{
			"#
		)?;

		for constant in &consts {
			writeln!(
				&libc_const_file,
				r#""{c}" => libc::{c}.to_string(),"#,
				c = constant
			)?;
		}

		writeln!(
			&libc_const_file,
			r#"
				_ => unreachable!("unknown command")
			}});
		}}"#
		)?;

		println!("wrote src/bin/libc-const.rs");
	}

	// for (name, def) in types {
	// 	println!("\n{} = {}", name, def);
	// }

	// libc-def
	{
		println!("resolving {} types", types.len());
		types.resolve_all()?;
		let types = types.finalise();

		println!("writing types");
		let libc_def_file = File::create("src/bin/libc-def.rs")?;
		writeln!(
			&libc_def_file,
			r#"
			#[rustfmt::skip]
			#[allow(deprecated)]
			fn main() {{
				let args = clap::App::new("defnew")
					.author(&*format!(
						"CC BY-SA-NC 4.0 - {{}}",
						env!("CARGO_PKG_HOMEPAGE")
					))
					.about("libc-def: provides defs for libc types")
					.after_help("Defs are hard-coded at compile and are not guaranteed to be correct for your system.")
					.version(clap::crate_version!())
					.setting(clap::AppSettings::SubcommandRequired)
			"#
		)?;

		for (name, _) in &types {
			writeln!(
				&libc_def_file,
				r#".subcommand(clap::SubCommand::with_name("{}"))"#,
				name
			)?;
		}

		writeln!(
			&libc_def_file,
			r#"
			.get_matches();

			println!("{{}}", match args.subcommand_name().unwrap() {{
			"#
		)?;

		for (name, value) in &types {
			writeln!(
				&libc_def_file,
				r##""{name}" => r#"{value}"#,"##,
				name = name,
				value = value,
			)?;
		}

		writeln!(
			&libc_def_file,
			r#"
				_ => unreachable!("unknown command")
			}});
		}}"#
		)?;

		println!("wrote src/bin/libc-def.rs");
	}

	Ok(())
}

fn parse_file(html_file: impl AsRef<Path>) -> Result<NodeRef, io::Error> {
	parse_html().from_utf8().from_file(html_file)
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
enum MaybeType {
	Raw {
		name: Option<String>,
		typ: String,
	},
	Struct {
		name: Option<String>,
		fields: Vec<Self>,
		align: Option<u64>,
		packed: Option<u64>,
	},
	Array {
		name: Option<String>,
		typ: Box<Self>,
		len: u64,
	},
	Def {
		name: Option<String>,
		def: Def,
	},
	Pointed {
		name: Option<String>,
		mutable: bool,
		typ: Box<Self>,
	},
	Opaque {
		name: Option<String>,
	},
}

impl MaybeType {
	fn from_type(name: Option<String>, ty: Type) -> Result<Self, Error> {
		use syn::{Expr, ExprLit, Lit, TypeArray, TypePath, TypePtr};

		if let Type::Ptr(TypePtr {
			elem, mutability, ..
		}) = ty
		{
			let inner = Self::from_type(None, *elem)?;
			let mutable = mutability.is_some();
			return Ok(Self::Pointed {
				name,
				mutable,
				typ: Box::new(inner),
			});
		}

		match ty {
			Type::Path(TypePath { path, .. }) => {
				let typestr = path
					.get_ident()
					.map(|ident| ident.to_string())
					.ok_or(Error::MissingType)?;

				Ok(match parse_def(&typestr) {
					Ok(def) => Self::Def { name, def },
					Err(_) => Self::Raw {
						name,
						typ: typestr.into(),
					},
				})
			}
			Type::Array(TypeArray {
				elem,
				len: Expr::Lit(ExprLit {
					lit: Lit::Int(len), ..
				}),
				..
			}) => {
				let typ = Box::new(Self::from_type(None, *elem)?);
				let len = len.base10_parse().map_err(Error::LiteralNotUsize)?;
				Ok(Self::Array { name, typ, len })
			}
			Type::Array(_) => Err(Error::UnsupportedType(
				"array with non-literal length",
				format!("{:#?}", ty),
			)),
			_ => Err(Error::UnsupportedType("?", format!("{:#?}", ty))),
		}
	}

	fn from_type_file(path: impl AsRef<Path>) -> Result<Self, About> {
		(|path| -> Result<_, Error> {
			let html = parse_file(path)?;
			let typedef = html
				.select_first(".rust.typedef")
				.or(Err(Error::NoMatch))?
				.text_contents();

			use syn::{parse_str, ItemType};

			let item: ItemType = parse_str(&typedef)?;
			Self::from_type(Some(item.ident.to_string()), *item.ty)
		})(&path)
		.map_err(|err| About::a_file(path.as_ref(), err))
	}

	fn from_enum_file(path: impl AsRef<Path>) -> Result<Self, About> {
		(|path| -> Result<_, Error> {
			let html = parse_file(path)?;
			let typedef = html
				.select_first(".rust.enum")
				.or(Err(Error::NoMatch))?
				.text_contents();

			use syn::{parse_str, ItemEnum};
			let synitem: ItemEnum = parse_str(&typedef)?;

			if !synitem.variants.is_empty() {
				unimplemented!("non-empty enums");
			}

			let name = Some(synitem.ident.to_string());
			Ok(Self::Opaque { name })
		})(&path)
		.map_err(|err| About::a_file(path.as_ref(), err))
	}

	fn from_struct_file(path: impl AsRef<Path>) -> Result<Self, About> {
		(|path| -> Result<_, Error> {
			let html = parse_file(path)?;
			let typedef = html
				.select_first(".rust.struct")
				.or(Err(Error::NoMatch))?
				.text_contents();

			use syn::{parse_str, Fields, FieldsNamed, FieldsUnnamed, ItemStruct};

			let synitem: ItemStruct = parse_str(&typedef)?;

			let name = Some(synitem.ident.to_string());

			let fields = match synitem.fields {
				Fields::Unit => Vec::new(),
				Fields::Named(FieldsNamed { named: fields, .. })
				| Fields::Unnamed(FieldsUnnamed {
					unnamed: fields, ..
				}) => fields
					.iter()
					.map(|field| {
						Self::from_type(
							field.ident.as_ref().map(|n| n.to_string()),
							field.ty.clone(),
						)
					})
					.collect::<Result<Vec<_>, _>>()?,
			};

			let align = Self::extract_repr_attr(&synitem.attrs, "align")?.1;
			let (is_packed, pack) = Self::extract_repr_attr(&synitem.attrs, "packed")?;
			let packed = if is_packed { pack.or(Some(1)) } else { None };

			Ok(Self::Struct {
				name,
				fields,
				align,
				packed,
			})
		})(&path)
		.map_err(|err| About::a_file(path.as_ref(), err))
	}

	// (presence, value)
	fn extract_repr_attr(attrs: &[Attribute], name: &str) -> Result<(bool, Option<u64>), Error> {
		use syn::{Lit, Meta, MetaList, NestedMeta};

		for attr in attrs {
			if let Ok(Meta::List(MetaList { path, nested, .. })) = attr.parse_meta() {
				if path.is_ident(name) {
					return Ok((
						true,
						if let Some(NestedMeta::Lit(Lit::Int(int))) = nested.first() {
							Some(int.base10_parse()?)
						} else {
							None
						},
					));
				}

				if path.is_ident("repr") {
					if let Some(NestedMeta::Meta(Meta::List(MetaList { path, nested, .. }))) =
						nested.first()
					{
						if path.is_ident(name) {
							return Ok((
								true,
								if let Some(NestedMeta::Lit(Lit::Int(int))) = nested.first() {
									Some(int.base10_parse()?)
								} else {
									None
								},
							));
						}
					}
				}
			}
		}

		Ok((false, None))
	}

	fn name(&self) -> Option<String> {
		match self {
			Self::Raw { name, .. }
			| Self::Struct { name, .. }
			| Self::Array { name, .. }
			| Self::Def { name, .. }
			| Self::Opaque { name, .. }
			| Self::Pointed { name, .. } => name,
		}
		.as_ref()
		.map(|n| n.to_string())
	}
}

#[derive(Debug, Clone)]
struct TypeMap {
	map: HashMap<String, MaybeType>,
	raw_count: usize,
}

impl TypeMap {
	fn new() -> Self {
		let mut map = Self {
			map: HashMap::new(),
			raw_count: 0,
		};

		map.insert(MaybeType::Def {
			name: Some("c_void".into()),
			def: parse_def("u8").unwrap(),
		});

		map
	}

	fn len(&self) -> usize {
		self.map.len()
	}

	fn count_raws(t: &MaybeType) -> usize {
		match t {
			MaybeType::Def { .. } | MaybeType::Opaque { .. } => 0,
			MaybeType::Raw { .. } => 1,
			MaybeType::Struct { fields, .. } => fields.iter().map(|f| Self::count_raws(f)).sum(),
			MaybeType::Array { typ, .. } | MaybeType::Pointed { typ, .. } => Self::count_raws(typ),
		}
	}

	fn print_raws(t: &MaybeType, indent: usize) {
		let prefix = "-- ".repeat(indent);
		match t {
			MaybeType::Def { .. } | MaybeType::Opaque { .. } => {}
			raw @ MaybeType::Raw { .. } => println!(
				"{}{:?} ========================================",
				prefix, raw
			),
			MaybeType::Struct { fields, name, .. } => {
				println!("{}for struct {:?}", prefix, name);
				fields.iter().for_each(|f| Self::print_raws(f, indent + 1))
			}
			MaybeType::Array { typ, name, .. } => {
				println!("{}for array {:?}", prefix, name);
				Self::print_raws(typ, indent + 1)
			}
			MaybeType::Pointed { typ, name, .. } => {
				println!("{}for pointed {:?}", prefix, name);
				Self::print_raws(typ, indent + 1)
			}
		}
	}

	fn insert(&mut self, t: MaybeType) {
		let name = t.name().expect("cannot insert unnamed type");

		for ignore in &IGNORED_TYPES {
			if ignore == &name {
				return;
			}
		}

		self.raw_count += Self::count_raws(&t);
		self.map.insert(name, t);
	}

	fn get_def(&self, name: &str) -> Option<Def> {
		if let Some(MaybeType::Def { def, .. }) = self.map.get(name) {
			Some(def.clone())
		} else {
			None
		}
	}

	fn get_resolved_type(&self, rtype: &MaybeType) -> Option<MaybeType> {
		match rtype {
			MaybeType::Raw { .. } => return None,
			MaybeType::Def { .. } | MaybeType::Opaque { .. } => {}
			MaybeType::Array { typ, .. } | MaybeType::Pointed { typ, .. } => {
				if self.get_resolved_type(typ).is_none() {
					return None;
				}
			}
			MaybeType::Struct { fields, .. } => {
				for field in fields {
					if self.get_resolved_type(field).is_none() {
						return None;
					}
				}
			}
		}

		Some(rtype.clone())
	}

	fn get_resolved(&self, name: &str) -> Option<MaybeType> {
		self.map.get(name).and_then(|t| self.get_resolved_type(t))
	}

	fn resolve_type(&self, rtype: &mut MaybeType) -> usize {
		match rtype {
			MaybeType::Raw { typ, .. } => {
				if let Some(def) = self.get_def(typ) {
					*rtype = MaybeType::Def {
						name: rtype.name(),
						def,
					};

					1
				} else if let Some(restyp) = self.get_resolved(typ) {
					*rtype = restyp;

					1
				} else {
					0
				}
			}
			MaybeType::Struct { fields, .. } if !fields.is_empty() => fields
				.iter_mut()
				.map(|field| self.resolve_type(field))
				.sum(),
			MaybeType::Array { typ, .. } | MaybeType::Pointed { typ, .. } => self.resolve_type(typ),
			_ => 0,
		}
	}

	fn resolve_once(&mut self) {
		let snapshot = self.clone();
		for (_, rtype) in self.map.iter_mut() {
			self.raw_count -= snapshot.resolve_type(rtype);
		}
	}

	fn resolve_all(&mut self) -> Result<(), Error> {
		let total = self.raw_count;
		const TRIES: usize = 7;

		let mut tries = 0;
		while tries < TRIES {
			tries += 1;
			self.resolve_once();

			if self.raw_count == 0 {
				return Ok(());
			}
		}

		for (_, typ) in self.map.iter() {
			Self::print_raws(typ, 0);
		}

		Err(Error::UnresolvedDefs {
			total,
			left: self.raw_count,
		})
	}

	fn finalise_type(typ: MaybeType) -> Def {
		use defnew::{
			def::{
				pointer::Context, r#struct::Field, Alignment, Array, ByteWidth, Pointer, Struct,
			},
			platform::native,
		};
		use std::num::NonZeroU64;

		match typ {
			MaybeType::Raw { .. } => {
				unreachable!("no raw types should remain before finalise phase")
			}
			MaybeType::Def { def, .. } => def,
			MaybeType::Opaque { .. } => Def::Opaque,
			MaybeType::Pointed { mutable, typ, .. } => Def::Pointer(Pointer {
				endian: native::ENDIAN,
				width: ByteWidth::new(native::POINTER_WIDTH).unwrap(),
				context: Context::Remote,
				mutable,
				value: 0,
				def: Some(Box::new(Self::finalise_type(*typ))),
			}),
			MaybeType::Struct {
				fields,
				name,
				packed,
				align,
			} => Def::Struct(Struct {
				name,
				align: align.map(|p| Alignment::new(p).expect("invalid struct align alignment")),
				packed: packed.map(|p| Alignment::new(p).expect("invalid struct packed alignment")),
				fields: fields
					.into_iter()
					.map(|f| Field {
						name: f.name(),
						def: Self::finalise_type(f),
					})
					.collect(),
			}),
			MaybeType::Array { name, typ, len } => Def::Array(Array {
				name: name.clone(),
				length: if len == 0 {
					None
				} else {
					Some(
						NonZeroU64::new(len)
							.expect(&format!("invalid array length ({}) for {:?}", len, name)),
					)
				},
				stride: None,
				def: Box::new(Self::finalise_type(*typ)),
			}),
		}
	}

	fn finalise(self) -> HashMap<String, Def> {
		self.map
			.into_iter()
			.map(|(k, m)| (k, Self::finalise_type(m)))
			.collect()
	}
}
