#!/usr/bin/env bash

if [ -d "$HOME/.rustup/toolchains" ] && [ -f "$HOME/.cargo/env" ]; then
    source ~/.cargo/env
    rustup toolchain install stable # also updates
    rustup default stable
else
    curl https://sh.rustup.rs -sSf | bash -s -- -y
    source ~/.cargo/env
fi

cd test-wrapper
cargo build --release
