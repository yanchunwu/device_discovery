CXX := g++
CXXFLAGS := -std=c++17 -O2 -Wall -Wextra
TEST_CXXFLAGS := $(CXXFLAGS) -Wno-unused-function
BIN_DIR := bin
TARGET := $(BIN_DIR)/infer_iot_raw
SRC := infer_iot_raw.cpp
TEST_DIR := tests
TEST_SRC := $(TEST_DIR)/test_infer_iot_raw.cpp
TEST_TARGET := $(BIN_DIR)/test_infer_iot_raw
PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin
DESTDIR ?=
INSTALL_DEST := $(DESTDIR)$(BINDIR)/infer_iot_raw
COMPLETION_DIR ?= $(PREFIX)/share/bash-completion/completions
COMPLETION_SRC := completions/infer_iot_raw.bash
COMPLETION_DEST := $(DESTDIR)$(COMPLETION_DIR)/infer_iot_raw

.PHONY: all clean test install install-cap install-bash-completion

all: $(TARGET)

$(TARGET): $(SRC)
	mkdir -p $(BIN_DIR)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(SRC)

$(TEST_TARGET): $(TEST_SRC) $(SRC)
	mkdir -p $(BIN_DIR)
	$(CXX) $(TEST_CXXFLAGS) -DINFER_IOT_RAW_TEST -o $(TEST_TARGET) $(TEST_SRC)

test: $(TEST_TARGET)
	./$(TEST_TARGET)

clean:
	rm -f $(TARGET) $(TEST_TARGET)

install: $(TARGET)
	install -Dm755 $(TARGET) $(INSTALL_DEST)

install-cap: $(TARGET)
	setcap cap_net_raw+ep $(TARGET)

install-bash-completion: $(COMPLETION_SRC)
	install -Dm644 $(COMPLETION_SRC) $(COMPLETION_DEST)
