struct Layout {
	lays: Vec<Def>,
}

impl Layout {
	fn fold(&self, op: impl Fn(&Def)) {
		self.fold_impl(op)
	}

	fn fold_impl<F>(&self, op: F)
	where
		F: Fn(&Def),
	{
		for lay in &self.lays {
			op(lay);
			lay.layout().fold_impl(&op);
		}
	}
}

// impl Layout {
// 	fn fold(&self, op: impl Fn(&Def)) {
// 		self.fold_impl(op);
// 	}

// 	fn fold_impl<F>(&self, mut op: F) -> F
// 	where
// 		F: Fn(&Def),
// 	{
// 		for lay in &self.lays {
// 			op(lay);
// 			op = lay.layout().fold_impl(op);
// 		}

// 		op
// 	}
// }

#[derive(Clone)]
struct Def;

impl Def {
	fn layout(&self) -> Layout {
		unimplemented!()
	}
}

fn main() {
	let def = Def;
	let layout = def.layout();
	show_fields(&layout);
}

fn show_fields(layout: &Layout) {
	layout.fold(|_| ())
}
