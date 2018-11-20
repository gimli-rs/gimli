#!/usr/bin/env bash

set -ex

case "$GIMLI_JOB" in
    "build")
        cargo build $GIMLI_PROFILE
        cargo build --release $GIMLI_PROFILE
        ;;

    "test")
        cargo build $GIMLI_PROFILE
        cargo test $GIMLI_PROFILE
        cargo build --release $GIMLI_PROFILE
        cargo test --release $GIMLI_PROFILE
        case "$TRAVIS_OS_NAME" in
            "osx")
                with_debug_info=$(find ./target/debug -type f | grep DWARF | grep gimli | head -n 1)
                ;;
            "linux")
                with_debug_info=$(find ./target/debug -type f -perm -100 | grep gimli | head -n 1)
                ;;
            *)
                echo "Error! Unknown \$TRAVIS_OS_NAME: $TRAVIS_OS_NAME"
                exit 1
        esac
        cargo run           --example dwarfdump -- "$with_debug_info" > /dev/null
        cargo run --release --example dwarfdump -- "$with_debug_info" > /dev/null
        ;;

    "doc")
        cargo doc
        ;;

    "alloc")
        test "$TRAVIS_RUST_VERSION" == "nightly"
        cargo build           --no-default-features --features read,alloc $GIMLI_PROFILE
        cargo build --release --no-default-features --features read,alloc $GIMLI_PROFILE
        ;;

    "bench")
        cargo bench
        ;;

    "coverage")
        RUSTFLAGS="--cfg procmacro2_semver_exempt" cargo install --force cargo-tarpaulin
        cargo tarpaulin --verbose --ciserver travis-ci --coveralls "$TRAVIS_JOB_ID";
        ;;

    "cross")
        rustup target add $TARGET
        cargo install cross --force
        cross test --target $TARGET $GIMLI_PROFILE
        ;;

    *)
        echo "Error! Unknown \$GIMLI_JOB: $GIMLI_JOB"
        exit 1
esac
