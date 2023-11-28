E3DB-Core --- Platform Agnostic E3DB Client Kernel
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

For Examples on how to Run and Build look in the [Example Folder](./examples/Example.md)

# Build with CMake

To build with CMake:

Note: *These instruction are for Linux command line only for now.*

```
$ mkdir build
$ cd build
$ cmake ..
$ make
```

Then to run command line from the `build` directory:

```
$ ./cmd/e3db <params>
```
or
```
$ ./examples/simple <params>
```

