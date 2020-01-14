LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_SRC_FILES := write2stdin.cpp

LOCAL_MODULE := libwrite2stdin

LOCAL_CFLAGS := \
  -Wno-format

cmd-strip :=
include $(BUILD_SHARED_LIBRARY)

include $(CLEAR_VARS)

LOCAL_SRC_FILES := afl-fuzzer.c

LOCAL_MODULE := libaflfuzzer

LOCAL_CFLAGS := \
  -Wno-format \
  -Wno-pointer-arith \
  -Wno-pointer-sign \
  -Wno-unused-parameter \
  -Wno-unused-variable

cmd-strip :=
include $(BUILD_SHARED_LIBRARY)
