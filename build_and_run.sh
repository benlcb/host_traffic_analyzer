#!/bin/bash 

cargo xtask build-ebpf
cargo build
RUST_LOG=info cargo xtask run