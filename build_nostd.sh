#!/bin/sh
# Due to the fact that cargo does not disable default features when we use
# cargo build --all --no-default-features we have to explicitly iterate over
# all crates (see https://github.com/rust-lang/cargo/issues/4753 )
DIRS=`ls -d */`
cargo clean

for DIR in $DIRS; do
    if [ $DIR = "target/" ]
    then
        continue
    fi
    cd $DIR
    xargo build --no-default-features --verbose --target $TARGET || {
        echo $DIR failed
        exit 1
    }
    cd ..
done
