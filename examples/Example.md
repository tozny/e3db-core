# e3db-core --- Platform agnostic e3db client kernel

# CLI Example

## Building the CLI

To build a local version of the command-line interface, check out the
sources locally, install dependencies

# How to Build

Run the following command to build an executable

```bash
git clone https://github.com/tozny/e3db-core
make all
```

# How to Run

To run the following library

```bash
./build/e3db [command]
```

To run Write Record

```bash

./build/e3db write-record -t recordTypeWanted -d @<PathToJSON>/examples/example_data.json  -m @<PathToJSON>/examples/example_meta.json

./build/e3db write-record -t recordTypeWanted -d @<PathToJSON>/examples/example_data.json  -m @<PathToJSON>/examples/example_meta.json -c <PathToJSON>/examples/config.json

./build/e3db write-record -t recordTypeWanted -d '{"key": "value"}'  -m '{"key": "value"}'

```

To run Read Record

```bash

./build/e3db read-record 4d289c9d-ffe4-45a9-a423-c8fdcf76ddd1

./build/e3db read-record -c <PathToJSON>/examples/config.json 4d289c9d-ffe4-45a9-a423-c8fdcf76ddd1

./build/e3db read-record 4d289c9d-ffe4-45a9-a423-c8fdcf76ddd1 b8a79ca6-c1c2-4bc4-9906-739e772ae110

```

# Example Simple Program
