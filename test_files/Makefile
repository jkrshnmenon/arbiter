CC = gcc
CFLAGS =
  
CUR_DIR = $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
SRC_DIR = $(CUR_DIR)
BUILD_DIR = $(CUR_DIR)/build
  
.PHONY: all run clean $(BUILD_DIR)/%

UNIT_SRCS := $(wildcard *.c)
UNIT_OBJS := ${addprefix $(BUILD_DIR)/,$(notdir $(UNIT_SRCS:.c=.elf))}

all: run 

run: $(UNIT_OBJS)

$(BUILD_DIR)/%.elf: $(SRC_DIR)%.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $<

$(BUILD_DIR):
	@mkdir -p $@

clean:
	rm -rf $(BUILD_DIR)
