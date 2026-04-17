CXX := g++
CXXFLAGS := -std=c++17 -O2 -Wall -Wextra
BIN_DIR := bin
TARGET := $(BIN_DIR)/infer_iot_raw
SRC := infer_iot_raw.cpp
COMPLETION_DIR ?= /usr/share/bash-completion/completions
COMPLETION_SRC := completions/infer_iot_raw
COMPLETION_DEST := $(COMPLETION_DIR)/infer_iot_raw

.PHONY: all clean install-cap install-bash-completion

all: $(TARGET)

$(TARGET): $(SRC)
	mkdir -p $(BIN_DIR)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(SRC)

clean:
	rm -f $(TARGET)

install-cap: $(TARGET)
	sudo setcap cap_net_raw+ep $(TARGET)

install-bash-completion: $(COMPLETION_SRC)
	sudo install -Dm644 $(COMPLETION_SRC) $(COMPLETION_DEST)
