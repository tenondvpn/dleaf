#!/bin/bash
set -e

export PATH=/root/.cargo/bin:$PATH
export ANDROID_HOME=/root/tools/android-sdk
export ANDROID_SDK_ROOT=/root/tools/android-sdk
export ANDROID_NDK_HOME=/root/tools/android-sdk/ndk/29.0.14206865
export NDK_HOME=$ANDROID_NDK_HOME

cd /root/dleaf
make android
