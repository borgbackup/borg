#!/usr/bin/env bash

if [ -d "$HOME/.rustup/toolchains" ] && [ -f "$HOME/.cargo/env" ]; then
    source ~/.cargo/env
    rustup toolchain install nightly # also updates
    rustup default nightly
else
    curl https://sh.rustup.rs -sSf | bash -s -- -y --default-toolchain nightly
    source ~/.cargo/env
fi

cd test-wrapper
cargo build --release
