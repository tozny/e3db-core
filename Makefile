#
# Makefile
#
# Copyright (C) 2017, Tozny, LLC.
# All Rights Reserved.
#

BUILD_DIR := build

SOURCES := $(wildcard src/*.c)
OBJECTS := $(patsubst %.c,$(BUILD_DIR)/%.o,$(SOURCES))
HEADERS := $(wildcard src/*.h)

TEST_SOURCES := $(wildcard tests/*.c)
TEST_OBJECTS := $(patsubst %.c,$(BUILD_DIR)/%.o,$(TEST_SOURCES))

LIB   := $(BUILD_DIR)/libe3db.a
TESTS := build/tests/list-records

all: $(LIB) $(TESTS)

$(LIB): $(OBJECTS)
	@printf "%-10s %s\n" "AR" "$@"
	@ar cru $(LIB) $(OBJECTS)

$(BUILD_DIR)/tests/%: $(BUILD_DIR)/tests/%.o $(LIB) $(HEADERS)
	@printf "%-10s %s\n" "LINK" "$@"
	@-mkdir -p $(dir $@)
	@gcc -g -o $@ -Isrc $< $(LIB) -lcurl -lssl -lcrypto -lm

$(BUILD_DIR)/%.o: %.c $(HEADERS)
	@printf "%-10s %s\n" "CC" "$@"
	@-mkdir -p $(dir $@)
	@gcc -g -Wall -Isrc -c -o $@ $<

clean:
	rm -rf $(BUILD_DIR)

# Stop GNU Make from removing object files resulting from chains
# of implicit rules.
.SECONDARY: $(OBJECTS) $(TEST_OBJECTS)
