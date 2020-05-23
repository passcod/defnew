# defnew

_A toolkit for interacting with C ABI binary data and libc, from a shell._

## Foreword

This is a personal project. I use it. It is not open source software, but you can use it, subject
to its license: [Creative Commons Attribution-ShareAlike-NonCommercial][license]. You may also
contribute: it operates on [the Caretaker model][caretaker] rather than usual open source rules.

The backstory for this project is that one day I bemoaned for the Nth time that I wasn't able to
just call arbitrary libc functions from my shell, and decided to do something about it, if I could.
Then came two months of occasional evenings and weekends building up to this goal.

Early on, I decided that this was not going to be a typical open source project, and that I would
explicitly _not_ make it "others-ready." That guiding principle allowed me to take shortcuts and
make allowances I would never have otherwise, and as a result, this work actually came to life.

## Introduction

Defnew is pronounced "deff new." It is both the concatenation of two tools in the kit, and a
contraction for "definitely new," as in this is definitely probably a new idea. Maybe. Who knows.

Defnew has three main parts: **def**initions, the **new** and **cast** tools, and **libc-\*** tools.

### Definitions

Defnew has its own format for expressing type information. Representationally, it is a s-expression.
This is for three reasons: one, the parser is already written (the `lexpr` crate) and as it is a
common format, many other languages and tools are able to parse it also; two, is it human-readable
and human-writable, supports comments, can be prettified, and so on; three, it is trivial to nest a
full **def** inside another **def** by simple string interpolation, such as is common in shells.

Let's go through some examples:

This is a def for a 16-bit unsigned integer, aka a `u16`:

```lisp
(integral (signed #f) (width 2))
```

This is a def for a struct with three fields: two `u64`s, and a boolean.

```lisp
(struct
	(field "fruit"
		(integral (signed #f) (width 8)))
	(field "sugar"
		(integral (signed #f) (width 8)))
	(field "cooked"
		(bool)))
```

Here, you can see that the `struct` def includes three s-exp which are themselves fully-formed defs.
You could form the above using this shell script:

```bash
u64="(integral (signed #f) (width 8))"
fruit="$u64"
sugar="$u64"
cooked="(bool)"

jam="(struct (field \"fruit\" $fruit) (field \"sugar\" $sugar) (field \"cooked\" $cooked))"
```

There are def forms for every type the C ABI supports, and a few it doesn't (used internally or for
low-level operations).

- Integrals/integers: signed or unsigned, of any byte width, of any endiannes.
- Floats: IEEE754, all variants. (Currently only Rust-supported variants can be newed and cast!)
- Booleans. (Also "wide" booleans, of any byte width.)
- Structs: fields can be named or unnamed independently, so tuples are possible, but also odd
	things like structs with half fields named and half unnamed. Can have alignment and packed.
- Arrays: including zero-length arrays. Custom strides are parsed but not observed (yet?).
- Enums: discriminants can be specified, or left to generate, or a combination. Width can be set.
- Unions.
- Pointers. (Has various internal/low-level details, won't get into it right now.)
- Opaques. (Low-level, used with pointers.)

Writing defs by hand can be cumbersome, so the `def` tool provides shell-friendly commands. The
above jam struct can be created like this:

```bash
def struct fruit:u64 sugar:u64 cooked:bool
```

However, if you run this, you'll notice the output is quite a bit longer than above! Furthermore,
it may be different based on your platform. Here's what I get (expanded for readability):

```lisp
(struct
	(size 24)
	(align 8)
	(field "fruit"
		(integral (signed #f) (endian little) (width 8)))
	(field "sugar"
		(integral (signed #f) (endian little) (width 8)))
	(field "cooked"
		(bool)))
```

Oh boy. What's all this?

Recall that Defnew is all about handling C ABI data. To do that, it needs to know the precise
layout of the data. So in this "normalised" output, it includes a lot of information that is
defaulted or platform-dependent when we use the shorter, human-friendly forms from before.

Above, we didn't specify an endianness. That defaults to `native`, and on my platform (x86_64),
this works out to `little`. We didn't specify a minimum alignment for the struct, so defnew
computed it for us and found `8`. And though defnew ignores this on reading, it calculates and
provides the size of the struct in bytes, for convenience.

But wait, if endianness defaults to `native`, why output it as `little` here?

Well, defs are meant to encode all the information needed that, when shipped alongside or specified
for, a piece of data, that data should correctly decode. If a little-endian platform makes data and
passes it along to a big-endian platform, the def needs to specify that integers are little-endian,
otherwise they won't decode correctly at all.

Coming back to the `def struct` call, you can see it used `u64` and `bool` directly. These are not
technically defs, but are _platform types_, which resolve to defs according to what the platform
does. Here's a list for x86_64:

- `bool`
- `u8`, `u16`, `u32`, `u64`, `u128`
- `i8`, `i16`, `i32`, `i64`, `i128`
- `f32`, `f64`
- `usize`, `isize`

Now, remember how we created the jam struct from bash, with interpolation? We can do that helped by
the `def` tool, too! This is a bit trivial because `def struct` handles simple types itself, but as
an example:

```bash
def struct "fruit:$(def uint 8)" "sugar:$(def uint 8)" "cooked:$(def bool)"
```

Because this is all shell interpolation and substitution, you can make types parametric based on
inputs to a script, accept arbitrary defs and wrap them, etc. Here's a short script that varies the
width of a uint based on what will fit the input, up to 32 bits:

```bash
#!/usr/bin/env bash

number="$1"
if [[ -z "$number" ]]; then
	echo "Usage: $0 <number>" >&2
	exit 1
fi

size=4
if [[ $number <= 255 ]]; then
	size=1
elif [[ $number <= 65535 ]]; then
	size=2
fi

def struct "number:$(def uint $size)"
```

Finally, the `def` tool can print out the precise memory layout of any def, whether when
constructing it using the convenience commands (`def struct`, `def uint`, etc), or for
any arbitrary def expression using `def parse`, with the `--show-layout` (`-L`) flag:

```bash
def --show-layout struct fruit:u64 sugar:u64 cooked:bool

00000000 -> 00000064       8 bytes  [Integral(Integral { signed: false, endian: Little, width: 8 })]
00000064 -> 00000128       8 bytes  [Integral(Integral { signed: false, endian: Little, width: 8 })]
00000128 -> 00000136       1 bytes  [Boolean(Boolean { width: 1 })]
00000136 -> 00000192       7 bytes  [Padding(56)]

(struct (size 24) (align 8) (field "fruit" (integral ...
```

The two leftmost columns show the start and end offsets of each item in _bits_, then the size of
the item in _bytes_, then a description (for now, in Rust debug format).

Notably, visible here is the padding: 56 bits or 7 bytes!

You can specify the `align` and `packed` layout options of a struct, to respectively raise or lower
its alignment, in accordance with C ABI rules. A more compact (but possibly less cache-friendly)
layout could be:

```bash
def --show-layout struct --packed 4 fruit:u64 sugar:u64 cooked:bool

00000000 -> 00000064       8 bytes  [Integral(Integral { signed: false, endian: Little, width: 8 })]
00000064 -> 00000128       8 bytes  [Integral(Integral { signed: false, endian: Little, width: 8 })]
00000128 -> 00000136       1 bytes  [Boolean(Boolean { width: 1 })]
00000136 -> 00000160       3 bytes  [Padding(24)]

(struct (size 20) (packed 4) (align 4) (field "fruit" (integral ...
```

Note that defnew is specifically concerned with the C layout. Struct fields always start at offset
zero, no reordering takes place, etc.

### Constructions: the `new` and `cast` tools

These two tools perform the opposite actions:

- **`new`** constructs a blob of binary according to the layout of a given **def** and some values.
- **`cast`** deconstructs a blob of binary according to a given **def** and outputs values.

This is what allows you to actually make use of defs and manipulate data. There's really not that
much complexity to it, so I'll show a few examples.

Assuming the jam def above (either the handcrafted or the normalised version) is in `$jamdef`:

```bash
new "$jamdef" 850 700 false

R
```

Err. What?

The `new` tool, by default, outputs on stdout. This is great for piping and general practice, but
not great for demonstration purposes. Let's get it in hex instead... by piping it to `hexdump`:

```bash
new "$jamdef" 850 700 true | hexdump -C

00000000  52 03 00 00 00 00 00 00  bc 02 00 00 00 00 00 00  |R...............|
00000010  01 00 00 00 00 00 00 00                           |........|
00000018
```

850 in decimal is `0x352`, and 700 is `0x2bc`, and in little-endian order, you can clearly see two
`u64`s (the first line, with two blocks of 8 bytes each), followed by a single 0x01 byte, followed
by seven other 0x00 bytes (the boolean and the padding).

That's our data, all laid out and properly written.

Now if we take that data and pass it back to `cast`, with that same def:

```bash
new "$jamdef" 850 700 true | cast "$jamdef"

fruit:  850
sugar:  700
cooked: true
```

Magical.

We can also do type punning or transmuting by using a different def on the output, and we're also
not obligated to decode _all_ the data. Let's cast out the first two bytes as... well, bytes:

```bash
new "$jamdef" 850 700 true | cast "$(def struct u8 u8)"

0:      82
1:      3
```

On Windows, it is illegal (and UB) to output non-UTF16 data on stdout. So both tools can also read
and write files, with `new -o path/to/file` and `cast -f path/to/file`.

`cast` can also output type information or the raw bytes of each field (in hex):

```bash
new "$jamdef" 850 700 true | cast "$jamdef" --with-defs --with-raws

fruit:  850     [52 03 00 00 00 00 00 00]       (integral (signed #f) (endian little) (width 8))
sugar:  700     [bc 02 00 00 00 00 00 00]       (integral (signed #f) (endian little) (width 8))
cooked: true    [01]    (bool)
```

It can write out in env format, to be sourced directly in a bash-like script without parsing:

```bash
new "$jamdef" 850 700 true | cast "$jamdef" -o env

fruit=850
sugar=700
cooked=true
```

And it can write types and raws like that too:


```bash
new "$jamdef" 850 700 true | cast "$jamdef" --with-defs --with-raws -o env

fruit='850'
fruit__DEF='(integral (signed #f) (endian little) (width 8))'
fruit__RAW='5203000000000000'
sugar='700'
sugar__DEF='(integral (signed #f) (endian little) (width 8))'
sugar__RAW='bc02000000000000'
cooked='true'
cooked__DEF='(bool)'
cooked__RAW='01'
```

When constructing with `new`, padding is zeroes, which is different from how programs construct
values (where padding is undefined, and turns out to be garbage data), and omitted values are also
zeroes, which is different from how programs do it (in most languages) in that the compiler would
complain if you didn't fill all the fields.

Which brings us to pathing: how to specify which field gets which value.

Firstly, the `new` tool has a flag `--show-fields` or `-F` that will, instead of normal operation,
show the fields of the given def and two important values: the ARG and the STRUCTURAL PATH.

```bash
new "$jamdef" -F

[ARG]  STRUCTURAL PATH                      DESCRIPTION
[  0]  .fruit                               Integral(Integral { signed: false, endian: Little, width: 8 })
[  1]  .sugar                               Integral(Integral { signed: false, endian: Little, width: 8 })
[  2]  .cooked                              Boolean(Boolean { width: 1 })
```

The ARG is the "argument order", in which non-pathed arguments will be taken and applied to each
field. The STRUCTURAL PATH is how to specify fields regardless of order.

Here's various _equivalent_ calls for our example:

```bash
new "$jamdef" .fruit:850 .sugar:700 .cooked:true
new "$jamdef" .cooked:true .fruit:850 .sugar:700
new "$jamdef" .fruit:850 .sugar:700 true
new "$jamdef" .fruit:850 true .sugar:700
new "$jamdef" .sugar:700 850 true
```

And here's a demonstration of leaving all fields blank, creating an all-zero (but correctly-sized!)
binary blob:

```bash
new "$jamdef" | hexdump -C

00000000  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
00000010  00 00 00 00 00 00 00 00                           |........|
00000018
```

### libc tooling

WIP

no, like, really WIP, the actual tools aren't finished

What you can do so far:

- with `libc-const`, get the value (and the list, via help) of every constant in libc
- with `libc-def`, get the def of every top level type in libc
