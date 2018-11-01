#!/bin/sh
PATH=$PATH:/Library/Developer/CommandLineTools/usr/bin
CARGO_INCREMENTAL=0
cargo clean
cargo rustc -- --test -Clink-dead-code -Copt-level=1 -Ccodegen-units=1 -Zno-landing-pads -Cpasses=insert-gcov-profiling -L/Library/Developer/CommandLineTools/usr/lib/clang/10.0.0/lib/darwin/ -lclang_rt.profile_osx

# lcov --gcov-tool ./llvm-lcov --rc lcov_branch_coverage=1 --rc lcov_excl_line=assert --capture --directory . --base-directory . --no-external -o target/coverage/raw.lcov
# lcov --gcov-tool ./llvm-lcov --rc lcov_branch_coverage=1 --rc lcov_excl_line=assert --no-external --extract target/coverage/raw.lcov "$(pwd)/*" -o target/coverage/raw_crate.lcov

# genhtml --branch-coverage --demangle-cpp --legend -o target/coverage/ target/coverage/raw_crate.lcov