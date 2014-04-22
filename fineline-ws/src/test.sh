#!/bin/bash

make clean

make

echo "Starting test..."

if [ -e fineline-ws ]; then
   cp fineline-ws ../../testing/
   cd ../../testing/
   rm *.fle
   ./fineline-ws -w -i Windows.edb -f fl-file-filter-list-example.txt
   cd ../linux/fineline-ws/
fi
