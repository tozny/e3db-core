e3db-core --- Platform agnostic e3db client kernel
==================================================

# How to Build 

Clone the repository 

Run the following command to build an executable
```bash 
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
