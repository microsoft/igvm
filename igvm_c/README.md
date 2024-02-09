# IGVM C API

This folder contains a Makefile project that is used to build a C compatible API
from the igvm crate. The C API provides functions that can be used to parse and
validate a binary IGVM file and provides access to the fixed header and all of
the variable headers and associated file data.

The C API is generated directly from the rust source files. This includes the
definitions of the structures and enums in igvm_defs. This ensures that the C
API does not need to be manually updated inline with any changes to the rust
definitions.

## Dependencies
The C API header files are generated using the `cbindgen` tool. This tool needs
to be installed before the API can be built. This can be achieved using:

```bash
cargo install --force cbindgen
```

In addition, `sample/dump_igvm` and the C unit tests requires a C compiler to be
installed.

The unit tests require CUnit to be installed.

## Building
The C API can be built with:

```bash
make -f Makefile
```

This builds both the igvm and igvm_defs rust projects enabling the `igvm-c`
feature. In order to keep the C API build separate from the normal build, the
cargo target directory is set to `target_c`.

The following output files are generated for the build:

`target_c/[debug | release]/libigvm.a`: Static library that includes the
exported C functions.

`igvm_c/include/igvm_defs.h`: Definitions of the IGVM structures.
`igvm_c/include/igvm.h`: Declarations of the C API functions.

The file `igvm.h` includes `igvm_defs.h` so only this file needs to be included
in C projects source files.

## Sample application
The C API build generates a test application named `dump_igvm`. This application
can take the path of a binary IGVM file as a parameter and will use the C API to
parse the file and dump the contents to the console.

## Unit tests
A test executable is built and automatically invoked during the build process.
This performs a number tests to ensure the C API can parse a binary file and
allow access to the fixed header and each variable header type.

A simple rust project is provided in `igvm_c/test_data` that is used to generate
the test data for the unit tests. When adding or modifying tests or data, the
test data must be kept in sync with the expected results in the unit tests.
