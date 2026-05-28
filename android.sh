#!/bin/bash
set -e

if [ -d /root/.cargo/bin ]; then
    export PATH=/root/.cargo/bin:$PATH
fi

export ANDROID_HOME="${ANDROID_HOME:-/root/tools/android-sdk}"
export ANDROID_SDK_ROOT="${ANDROID_SDK_ROOT:-$ANDROID_HOME}"
export ANDROID_NDK_HOME="${ANDROID_NDK_HOME:-$ANDROID_HOME/ndk/29.0.14206865}"
export NDK_HOME=$ANDROID_NDK_HOME

cd "$(dirname "$0")"
make android

if [ -z "$JNILIBS_DIR" ]; then
    maybe_jni_dir="$(pwd)/../../jniLibs"
    if [ -d "$maybe_jni_dir" ]; then
        JNILIBS_DIR="$maybe_jni_dir"
    fi
fi

if [ -n "$JNILIBS_DIR" ]; then
    mkdir -p "$JNILIBS_DIR/armeabi-v7a" "$JNILIBS_DIR/x86" "$JNILIBS_DIR/x86_64" "$JNILIBS_DIR/arm64-v8a"
    cp target/armv7-linux-androideabi/release/libleafandroid.so "$JNILIBS_DIR/armeabi-v7a/"
    cp target/i686-linux-android/release/libleafandroid.so "$JNILIBS_DIR/x86/"
    cp target/x86_64-linux-android/release/libleafandroid.so "$JNILIBS_DIR/x86_64/"
    cp target/aarch64-linux-android/release/libleafandroid.so "$JNILIBS_DIR/arm64-v8a/"
fi
