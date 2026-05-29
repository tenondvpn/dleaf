#!/bin/bash
set -euo pipefail

mode=release
if [ "${1:-release}" = "debug" ]; then
    mode=debug
fi
build_simulator="${BUILD_IOS_SIMULATOR:-1}"

base="$(cd "$(dirname "$0")" && pwd)"
out_dir="${2:-$base/../Fluters/ios/vpnPacketTunnel/libleaf}"
profile_arg=()
if [ "$mode" = "release" ]; then
    profile_arg=(--release)
fi

if command -v cargo >/dev/null 2>&1; then
    cargo_cmd=(cargo)
elif command -v rustup >/dev/null 2>&1; then
    cargo_cmd=(rustup run stable cargo)
    export RUSTC="$(rustup which --toolchain stable rustc)"
else
    echo "cargo/rustup is not available" >&2
    exit 1
fi

if ! command -v cbindgen >/dev/null 2>&1; then
    export PATH="$HOME/.cargo/bin:$PATH"
fi

if ! command -v cbindgen >/dev/null 2>&1; then
    echo "cbindgen is not available" >&2
    exit 1
fi

targets=(
    aarch64-apple-ios
)
if [ "$build_simulator" = "1" ]; then
    targets+=(
        aarch64-apple-ios-sim
        x86_64-apple-ios
    )
fi

if command -v rustup >/dev/null 2>&1; then
    rustup target add "${targets[@]}"
fi

wrapper_dir="$base/target/ios-cc-wrappers"
mkdir -p "$wrapper_dir"
cat > "$wrapper_dir/iphoneos-clang" <<'EOF'
#!/bin/sh
exec xcrun --sdk iphoneos clang "$@"
EOF
cat > "$wrapper_dir/iphonesimulator-clang" <<'EOF'
#!/bin/sh
exec xcrun --sdk iphonesimulator clang "$@"
EOF
chmod +x "$wrapper_dir/iphoneos-clang" "$wrapper_dir/iphonesimulator-clang"

apple_ar="$(xcrun --find ar)"
export CC_aarch64_apple_ios="$wrapper_dir/iphoneos-clang"
export AR_aarch64_apple_ios="$apple_ar"
export CC_aarch64_apple_ios_sim="$wrapper_dir/iphonesimulator-clang"
export AR_aarch64_apple_ios_sim="$apple_ar"
export CC_x86_64_apple_ios="$wrapper_dir/iphonesimulator-clang"
export AR_x86_64_apple_ios="$apple_ar"

for target in "${targets[@]}"; do
    "${cargo_cmd[@]}" build \
        --manifest-path "$base/Cargo.toml" \
        -p leaf-ffi \
        --target "$target" \
        --no-default-features \
        --features default-ring \
        ${profile_arg+"${profile_arg[@]}"}
done

mkdir -p "$out_dir/iphoneos" "$out_dir/iphonesimulator"
cp "$base/target/aarch64-apple-ios/$mode/libleaf.a" "$out_dir/iphoneos/libleaf.a"
if [ "$build_simulator" = "1" ]; then
    xcrun lipo -create \
        "$base/target/aarch64-apple-ios-sim/$mode/libleaf.a" \
        "$base/target/x86_64-apple-ios/$mode/libleaf.a" \
        -output "$out_dir/iphonesimulator/libleaf.a"
fi

cbindgen --config "$base/leaf-ffi/cbindgen.toml" "$base/leaf-ffi/src/lib.rs" > "$out_dir/leaf.h"

file "$out_dir/iphoneos/libleaf.a"
if [ "$build_simulator" = "1" ]; then
    file "$out_dir/iphonesimulator/libleaf.a"
fi
