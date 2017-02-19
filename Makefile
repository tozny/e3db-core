#
# Makefile
#
# Copyright (C) 2017, Tozny, LLC.
# All Rights Reserved.
#

VERSION        := 0.0.1
TESTS          := build/tests/list-records
PUBLIC_HEADERS := src/e3db_core.h

BUILD_DIR      := build
LIB            := $(BUILD_DIR)/libe3db.a

SOURCES        := $(wildcard src/*.c)
OBJECTS        := $(patsubst %.c,$(BUILD_DIR)/%.o,$(SOURCES))
HEADERS        := $(wildcard src/*.h)

TEST_SOURCES   := $(wildcard tests/*.c)
TEST_OBJECTS   := $(patsubst %.c,$(BUILD_DIR)/%.o,$(TEST_SOURCES))

UNAME := $(shell uname)

ifeq ($(UNAME),Darwin)
DIST_ZIP  := e3db-core-macosx-$(VERSION).zip
else
ifeq ($(UNAME),Linux)
DIST_ZIP  := e3db-core-linux-$(VERSION).zip
else
$(error "Unknown operating system.")
endif
endif

DIST_DIR  := $(BUILD_DIR)/dist
DIST_PRE  := ../..
DIST_NAME := e3db-core-$(VERSION)
DIST_BASE := $(DIST_DIR)/$(DIST_NAME)

all: $(LIB) $(TESTS)

dist: $(DIST_ZIP)

$(DIST_ZIP): $(LIB) $(PUBLIC_HEADERS)
	@printf "%-10s %s\n" "ZIP" "$@"
	@rm -rf $(DIST_ZIP) $(DIST_BASE)
	@mkdir -p $(DIST_BASE)/include $(DIST_BASE)/lib
	@cp $(PUBLIC_HEADERS) $(DIST_BASE)/include
	@cp $(LIB) $(DIST_BASE)/lib
	@cd $(DIST_DIR) && zip -qr $(DIST_PRE)/$(DIST_ZIP) $(DIST_NAME)

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
	rm -rf $(BUILD_DIR) $(DIST_ZIP)

# Stop GNU Make from removing object files resulting from chains
# of implicit rules.
.SECONDARY: $(OBJECTS) $(TEST_OBJECTS)

# vim: set noet ts=2:
