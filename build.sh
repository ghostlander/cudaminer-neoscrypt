#!/bin/bash

export PATH="$PATH:/usr/local/cuda/bin/"

make distclean

aclocal && autoheader && automake --add-missing --gnu --copy && autoconf

rm -f config.status

FLAGS="-march=native -falign-functions=16 -falign-jumps=16 -falign-labels=16"

env CUDA_CFLAGS="-O3 -Xcompiler -Wall -D_FORCE_INLINES" CFLAGS="-O2 -fomit-frame-pointer $FLAGS" \
CXXFLAGS="-O2 -fomit-frame-pointer -fno-stack-protector $FLAGS" ./configure

make
