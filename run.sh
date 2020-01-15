#!/bin/bash

Usage() {
  cat <<EOF
USAGE:
  $(basename $0) [OPTIONS]
  Options:
    -f
      afl_fuzz path, default py-afl_fuzz
    -b
      target binary path, required
    -j
      parallel jobs, default 1
    -m
      memory limit, default no limit
    -t
      timeout, default 1000ms
    -x
      dict
    -i
      input
    -o
      output
    -h
      this help message
EOF

  exit 1
}

FUZZ="py-afl-fuzz"
JOBS=1
MEMORY=none
TIMEOUT=1000
INPUT=cases
OUT=findings

while getopts "hf:b:j:m:t:x:i:o:" o; do
  case "$o" in
    f) FUZZ="$OPTARG";;
    b) BINARY="$OPTARG";;
    j) JOBS="$OPTARG";;
    m) MEMORY="$OPTARG";;
    t) TIMEOUT="$OPTARG";;
    i) INPUT="$OPTARG";;
    x) DICT="$OPTARG";;
    o) OUT="$OPTARG";;
    h) Usage;;
  esac
done
shift $((OPTIND-1))

if [ "$BINARY" == "" ]; then
  echo "Missing option -b"
  Usage
fi

mkdir -p $OUT
chmod a+xr $OUT

if [[ $JOBS -gt 1 ]]; then
  for i in $(seq 1 $(expr $JOBS - 1)); do
    if [ "$DICT" != "" ]; then
      exec $FUZZ -i $INPUT -o $OUT -x $DICT -m $MEMORY -t $TIMEOUT -S s$i -- $BINARY > $OUT/log-s$i &
    else
      exec $FUZZ -i $INPUT -o $OUT -m $MEMORY -t $TIMEOUT -S s$i -- $BINARY > $OUT/log-s$i &
    fi
  done
  if [ "$DICT" != "" ]; then
    exec $FUZZ -i $INPUT -o $OUT -x $DICT -m $MEMORY -t $TIMEOUT -M master -- $BINARY
  else
    exec $FUZZ -i $INPUT -o $OUT -m $MEMORY -t $TIMEOUT -M master -- $BINARY
  fi
else
  if [ "$DICT" != "" ]; then
    exec $FUZZ -i $INPUT -o $OUT -x $DICT -m $MEMORY -t $TIMEOUT -- $BINARY
  else
    exec $FUZZ -i $INPUT -o $OUT -m $MEMORY -t $TIMEOUT -- $BINARY
  fi
fi
