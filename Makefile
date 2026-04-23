CXX := g++
CXXFLAGS := -std=c++17 -O2 -Wall -Wextra
TEST_CXXFLAGS := $(CXXFLAGS) -Wno-unused-function
BIN_DIR := bin
TARGET := $(BIN_DIR)/infer_iot_raw
SRC := infer_iot_raw.cpp
TEST_DIR := tests
TEST_SRC := $(TEST_DIR)/test_infer_iot_raw.cpp
TEST_TARGET := $(BIN_DIR)/test_infer_iot_raw
INSTALL_DIR ?= /usr/local/bin
INSTALL_DEST := $(INSTALL_DIR)/infer_iot_raw
COMPLETION_DIR ?= /usr/share/bash-completion/completions
COMPLETION_SRC := completions/infer_iot_raw.bash
COMPLETION_DEST := $(COMPLETION_DIR)/infer_iot_raw

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
	sudo install -Dm755 $(TARGET) $(INSTALL_DEST)

install-cap: $(TARGET)
	sudo setcap cap_net_raw+ep $(TARGET)

install-bash-completion: $(COMPLETION_SRC)
	sudo install -Dm644 $(COMPLETION_SRC) $(COMPLETION_DEST)
