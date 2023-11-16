# e3db-core --- Platform agnostic e3db client kernel

# CLI Example

## How to Build

To build a local version of the command-line interface, check out the
sources locally, install dependencies
Run the following command to build an executable

```bash
git clone https://github.com/tozny/e3db-core
make all
```

#### Debug Build

For a debug build with Address Sanitizer enabled:

```bash
make debug
```

The debug build uses Address Sanitizer, a fast memory error detector. It's useful for detecting memory access issues in the code, such as buffer overflows, use-after-free, and memory leaks.

### How to Clean and Build

To clean and build the project:

```bash
make clean all
```

For a clean debug build:

```bash
make clean debug
```

## How to Run

To run the following library

```bash
./build/e3db [command]
```

Write Record

Write record takes 3 parameters, -r takes the record type for the record, -d takes the data meant to be encrypted for the record, and -m takes the plain meta fields used for advanced searching 

```bash

# Run write record with client configuration file found in ~/.tozny/e3db.json and the record data/meta found in a file
./build/e3db write-record -t recordTypeWanted -d @<PathToJSON>/examples/example_data.json  -m @<PathToJSON>/examples/example_meta.json

# Run write record with custom config file path and the record data/meta found in a file
./build/e3db write-record -t recordTypeWanted -d @<PathToJSON>/examples/example_data.json  -m @<PathToJSON>/examples/example_meta.json -c @<PathToJSON>/examples/config.json

# Run write record with client configuration file found in ~/.tozny/e3db.json and the record data/meta JSON blobs
./build/e3db write-record -t recordTypeWanted -d '{"key": "value"}'  -m '{"key": "value"}'

# Run write record with custom config file path and the record data/meta JSON blobs
./build/e3db write-record  -c @<PathToJSON>/examples/config.json -t recordTypeWanted -d '{"key": "value"}'  -m '{"key": "value"}'

```

Read Record

Read record takes a space separated list of record ids to fetch

```bash

# Run read record with client configuration file found in ~/.tozny/e3db.json
./build/e3db read-record 4d289c9d-ffe4-45a9-a423-c8fdcf76ddd1

# Run read record with custom config file path 
./build/e3db read-record -c @<PathToJSON>/examples/config.json 4d289c9d-ffe4-45a9-a423-c8fdcf76ddd1

# Run read record with multiple records 
./build/e3db read-record 4d289c9d-ffe4-45a9-a423-c8fdcf76ddd1 b8a79ca6-c1c2-4bc4-9906-739e772ae110

# Run read record with custom config file path and multiple records
./build/e3db read-record -c @<PathToJSON>/examples/config.json 4d289c9d-ffe4-45a9-a423-c8fdcf76ddd1 b8a79ca6-c1c2-4bc4-9906-739e772ae110

```

# Example Simple Program

### Prerequisite

Must have a Tozny Client Configuration File Located @ `~/.tozny/e3db.json`.

## How to Build

To build a small example project

```bash
git clone https://github.com/tozny/e3db-core
make simple
```

For a debug build of the simple project with Address Sanitizer enabled:

```bash
make debug-simple
```

### How to Clean and Build Simple Project

To clean and build the simple project:

```bash
make clean simple
```

For a clean debug build of the simple project:

```bash
make clean debug-simple
```

## How to Run

To run the following example project

```bash
./simple/simple 
```
