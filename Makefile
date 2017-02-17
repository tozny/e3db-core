
SOURCES := $(wildcard src/*.c)
HEADERS := $(wildcard src/*.h)

e3db-core-test: $(SOURCES) $(HEADERS)
	gcc -g -Wall -Isrc -o $@ $(SOURCES) -lcurl -lssl -lcrypto -lm

clean:
	rm -f e3db-core-test
