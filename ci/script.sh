#!/usr/bin/env bash

set -ex

case "$GIMLI_JOB" in
    "test")
        cargo clean
        cargo build $GIMLI_PROFILE
        cargo test $GIMLI_PROFILE
        ;;

    "examples")
        cargo build $GIMLI_PROFILE
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
        cargo run --example dwarfdump -- "$with_debug_info" > /dev/null
        ;;

    "doc")
        cargo doc
        ;;

    "alloc")
        test "$TRAVIS_RUST_VERSION" == "nightly"
        cargo clean
        cargo build --no-default-features --features alloc $GIMLI_PROFILE
        ;;

    "bench")
        cargo bench
        ;;

    "coverage")
        bash <(curl "https://raw.githubusercontent.com/xd009642/tarpaulin/master/travis-install.sh");
        cargo tarpaulin --verbose --no-count --ciserver travis-ci --coveralls "$TRAVIS_JOB_ID";
        ;;

    *)
        echo "Error! Unknown \$GIMLI_JOB: $GIMLI_JOB"
        exit 1
esac
