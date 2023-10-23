#
# Makefile
#
# Copyright (C) 2017, Tozny, LLC.
# All Rights Reserved.
#

VERSION        := 0.0.1
PUBLIC_HEADERS := src/e3db_core.h

BUILD_DIR      := build

SOURCES        := $(wildcard src/*.c)
OBJECTS        := $(patsubst %.c,$(BUILD_DIR)/%.o,$(SOURCES))
HEADERS        := $(wildcard src/*.h)
LIB            := $(BUILD_DIR)/libe3db.a
CFLAGS         := -Wall -g
LDFLAGS        :=
# CFLAGS         := -Wall -g -O1 -fsanitize=address
# LDFLAGS        := -fsanitize=address 

CMD_SOURCES    := $(wildcard cmd/*.c)
CMD_OBJECTS    := $(patsubst %.c,$(BUILD_DIR)/%.o,$(CMD_SOURCES))
CMD_HEADERS    := $(wildcard cmd/*.h)
CMD            := $(BUILD_DIR)/e3db

UNAME := $(shell uname)

ifeq ($(UNAME),Darwin)
DIST_NAME := e3db-core-macosx-$(VERSION)
CFLAGS    += -I/usr/local/opt/openssl/include
LDFLAGS   += -L/usr/local/opt/openssl/lib
else
ifeq ($(UNAME),Linux)
DIST_NAME := e3db-core-linux-$(VERSION)
else
$(error "Unknown operating system.")
endif
endif

DIST_DIR  := $(BUILD_DIR)/dist
DIST_PRE  := ../..
DIST_ZIP  := $(DIST_NAME).zip
DIST_BASE := $(DIST_DIR)/$(DIST_NAME)

all: $(LIB) $(CMD)

dist: $(DIST_ZIP)

$(DIST_ZIP): $(LIB) $(CMD) $(PUBLIC_HEADERS)
	@printf "%-10s %s\n" "ZIP" "$@"
	@rm -rf $(DIST_ZIP) $(DIST_BASE)
	@mkdir -p $(DIST_BASE)/include $(DIST_BASE)/lib $(DIST_BASE)/bin
	@cp $(PUBLIC_HEADERS) $(DIST_BASE)/include
	@cp $(LIB) $(DIST_BASE)/lib
	@cp $(CMD) $(DIST_BASE)/bin
	@cd $(DIST_DIR) && zip -qr $(DIST_PRE)/$(DIST_ZIP) $(DIST_NAME)

$(LIB): $(OBJECTS)
	@printf "%-10s %s\n" "AR" "$@"
	@ar cru $(LIB) $(OBJECTS)

$(CMD): $(CMD_OBJECTS) $(CMD_HEADERS) $(LIB) $(HEADERS)
	@printf "%-10s %s\n" "LINK" "$@"
	@-mkdir -p $(dir $@)
	@gcc $(CFLAGS) $(LDFLAGS) -o $@ -Isrc $< $(LIB) -lcurl -lssl -lcrypto -lm -lsodium

$(BUILD_DIR)/%.o: %.c $(HEADERS)
	@printf "%-10s %s\n" "CC" "$@"
	@-mkdir -p $(dir $@)
	@gcc $(CFLAGS) -Isrc -c -o $@ $<

clean:
	rm -rf $(BUILD_DIR) $(DIST_ZIP)

# Stop GNU Make from removing object files resulting from chains
# of implicit rules.
.SECONDARY: $(OBJECTS) $(CMD_OBJECTS)

# vim: set noet ts=2:
