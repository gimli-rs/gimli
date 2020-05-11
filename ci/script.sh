#!/usr/bin/env bash

set -ex

case "$GIMLI_JOB" in
    "test")
        cargo build
        cargo test
        cargo build --release
        cargo test --release
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

    "features")
        cargo test --no-default-features
        cargo test --no-default-features --features read
        cargo test --no-default-features --features read,fallible-iterator
        cargo test --no-default-features --features read,std
        cargo test --no-default-features --features read,endian-reader
        cargo test --no-default-features --features read,endian-reader,std
        cargo test --no-default-features --features write
        ;;

    "doc")
        cargo doc
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
        cross test --target $TARGET
        ;;

    *)
        echo "Error! Unknown \$GIMLI_JOB: $GIMLI_JOB"
        exit 1
esac
