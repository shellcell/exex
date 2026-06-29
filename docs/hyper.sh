#!/bin/sh
BIN=${1:-/bin/ls}
echo "\n============"
hyperfine \
    --warmup 5 \
    "exex '$BIN' -o strings" \
    "strings -a -t x '$BIN'"

echo "\n============"
hyperfine \
    --warmup 5 \
    "exex '$BIN' -o syms" \
    "nm -C -n -a '$BIN'"

echo "\n============"
hyperfine --warmup 5 \
  "exex '$BIN' -o sections" \
  "objdump -h '$BIN'"

echo "\n============"
hyperfine \
    "exex '$BIN' -o disasm" \
    "objdump -d '$BIN'" \
    "otool -tvV '$BIN'"

echo "\n============"
 hyperfine \
    "exex '$BIN' -o disasm-all" \
    "objdump -D '$BIN'"
