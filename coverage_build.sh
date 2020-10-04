#!/bin/sh
PATH=$PATH:/Library/Developer/CommandLineTools/usr/bin
export CARGO_INCREMENTAL=0
export RUSTFLAGS="-Zprofile -Clink-dead-code -Copt-level=0 -Ccodegen-units=1 -Zpanic_abort_tests -Cpanic=abort -Coverflow-checks=off -Zinstrument-coverage" 

rm *.profdata

cargo +nightly clean
cargo +nightly test

xcrun llvm-profdata merge -sparse -o chacha.profdata *.profraw   
xcrun llvm-cov show --show-regions --ignore-filename-regex="/rustc" --format=html -instr-profile=chacha.profdata --output-dir=./target/debug ./target/debug/deps/chacha-cefb82c7a65575f7