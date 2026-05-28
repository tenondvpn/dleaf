#!/bin/bash

set -e

mode=debug
if [ "$1" = "release" ]; then
    mode=release
fi

base="$(cd "$(dirname "$0")/.." && pwd)"
out_dir="${2:-$base/../Fluters/android/app/src/main/jniLibs}"
host_os="$(uname -s | tr "[:upper:]" "[:lower:]")"
host_arch="$(uname -m | tr "[:upper:]" "[:lower:]")"
android_tools="$NDK_HOME/toolchains/llvm/prebuilt/$host_os-$host_arch/bin"
api=26

if [ -z "$NDK_HOME" ]; then
    echo "NDK_HOME is not set"
    exit 1
fi

build_target() {
    local target="$1"
    local jni_dir="$2"
    local clang_target="${3:-$target}"
    local linker="$android_tools/${clang_target}${api}-clang"
    local ar="$android_tools/${target}-ar"

    mkdir -p "$out_dir/$jni_dir"
    case "$target" in
        x86_64-linux-android)
            export CC_x86_64_linux_android="$linker"
            export AR_x86_64_linux_android="$ar"
            export CARGO_TARGET_X86_64_LINUX_ANDROID_LINKER="$linker"
            export CARGO_TARGET_X86_64_LINUX_ANDROID_AR="$ar"
            ;;
        aarch64-linux-android)
            export CC_aarch64_linux_android="$linker"
            export AR_aarch64_linux_android="$ar"
            export CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER="$linker"
            export CARGO_TARGET_AARCH64_LINUX_ANDROID_AR="$ar"
            ;;
        i686-linux-android)
            export CC_i686_linux_android="$linker"
            export AR_i686_linux_android="$ar"
            export CARGO_TARGET_I686_LINUX_ANDROID_LINKER="$linker"
            export CARGO_TARGET_I686_LINUX_ANDROID_AR="$ar"
            ;;
        armv7-linux-androideabi)
            export CC_armv7_linux_androideabi="$linker"
            export AR_armv7_linux_androideabi="$ar"
            export CARGO_TARGET_ARMV7_LINUX_ANDROIDEABI_LINKER="$linker"
            export CARGO_TARGET_ARMV7_LINUX_ANDROIDEABI_AR="$ar"
            ;;
    esac

    if [ "$mode" = "release" ]; then
        cargo build --manifest-path "$base/Cargo.toml" -p leaf-android --target "$target" --no-default-features --features default-ring --release
    else
        cargo build --manifest-path "$base/Cargo.toml" -p leaf-android --target "$target" --no-default-features --features default-ring
    fi

    cp "$base/target/$target/$mode/libleafandroid.so" "$out_dir/$jni_dir/"
}

build_target x86_64-linux-android x86_64
build_target aarch64-linux-android arm64-v8a
build_target i686-linux-android x86
build_target armv7-linux-androideabi armeabi-v7a armv7a-linux-androideabi
