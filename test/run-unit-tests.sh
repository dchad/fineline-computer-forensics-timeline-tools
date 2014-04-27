#!/bin/bash

cd ../fineline
make clean
make

cd ../fineline-ie
make clean
make

cd ../fineline-iepre10
make clean
make

cd ../fineline-ws
make clean
make

cd ../fineline-search
make clean
make

../fineline-search/fineline-search-unit_tests


echo "Completed unit tests..."
