#!/bin/bash
set -euo pipefail

mode=release
if [ "${1:-release}" = "debug" ]; then
    mode=debug
fi

base="$(cd "$(dirname "$0")" && pwd)"
out_dir="${2:-$base/../Fluters/macos/Runner/Leaf}"
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
    aarch64-apple-darwin
    x86_64-apple-darwin
)

if command -v rustup >/dev/null 2>&1; then
    rustup target add "${targets[@]}"
fi

wrapper_dir="$base/target/macos-cc-wrappers"
mkdir -p "$wrapper_dir"
cat > "$wrapper_dir/macos-clang" <<'EOF'
#!/bin/sh
exec xcrun --sdk macosx clang "$@"
EOF
chmod +x "$wrapper_dir/macos-clang"

apple_ar="$(xcrun --find ar)"
export CC_aarch64_apple_darwin="$wrapper_dir/macos-clang"
export AR_aarch64_apple_darwin="$apple_ar"
export CC_x86_64_apple_darwin="$wrapper_dir/macos-clang"
export AR_x86_64_apple_darwin="$apple_ar"

for target in "${targets[@]}"; do
    "${cargo_cmd[@]}" build \
        --manifest-path "$base/Cargo.toml" \
        -p leaf-ffi \
        --target "$target" \
        --no-default-features \
        --features default-ring \
        ${profile_arg+"${profile_arg[@]}"}
done

mkdir -p "$out_dir"
xcrun lipo -create \
    "$base/target/aarch64-apple-darwin/$mode/libleaf.a" \
    "$base/target/x86_64-apple-darwin/$mode/libleaf.a" \
    -output "$out_dir/libleaf.a"

cbindgen --config "$base/leaf-ffi/cbindgen.toml" "$base/leaf-ffi/src/lib.rs" > "$out_dir/leaf.h"

file "$out_dir/libleaf.a"
