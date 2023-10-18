e3db-core --- Platform agnostic e3db client kernel
==================================================
# Overview

TozStore is an end-to-end encrypted database (E3DB). It's a storage platform
with powerful sharing and consent management features.
[Read more on our website.](https://tozny.com/tozstore)

TozStore provides a familiar JSON-based NoSQL-style API for reading, writing,
and querying data stored securely in the cloud.

This repository contains a client library and command-line tool E3DB.

# Command-Line Interface

The E3DB command-line interface (CLI) is a powerful tool for administrating
and interacting with the E3DB service. Binary releases for many
platforms are available from this project's Releases page.

## Building the CLI

To build a local version of the command-line interface, check out the
sources locally, install
dependencies, and build the `github.com/tozny/e3db/cmd/e3db` package:

# How to Build 

Run the following command to build an executable
```bash 
git clone https://github.com/tozny/e3db-core
make all 
```

To run the following library 
```bash
./build/e3db [command]
```


To run Write Record
```bash

./build/e3db write-record -t recordTypeWanted -d @<PathToJSON>/example_data.json  -m @<PathToJSON>/example_meta.json

./build/e3db write-record -t recordTypeWanted -d '{"key": "value"}'  -m '{"key": "value"}'

```
