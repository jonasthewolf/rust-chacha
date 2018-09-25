#!/bin/sh
PATH=$PATH:/Library/Developer/CommandLineTools/usr/bin
CARGO_INCREMENTAL=0
cargo clean
cargo rustc -- --test -Clink-dead-code -Copt-level=1 -Ccodegen-units=1 -Zno-landing-pads -Cpasses=insert-gcov-profiling -L/Library/Developer/CommandLineTools/usr/lib/clang/10.0.0/lib/darwin/ -lclang_rt.profile_osx