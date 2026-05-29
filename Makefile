ios:
	cargo lipo --release -p leaf-ffi
	cbindgen --config leaf-ffi/cbindgen.toml leaf-ffi/src/lib.rs > target/universal/release/leaf.h

ios-dev:
	cargo lipo -p leaf-ffi
	cbindgen --config leaf-ffi/cbindgen.toml leaf-ffi/src/lib.rs > target/universal/debug/leaf.h

ios-opt:
	cargo lipo --release --targets aarch64-apple-ios --manifest-path leaf-ffi/Cargo.toml --no-default-features --features "default-openssl"
	cbindgen --config leaf-ffi/cbindgen.toml leaf-ffi/src/lib.rs > target/universal/release/leaf.h

lib:
	cargo build -p leaf-ffi --release
	cbindgen --config leaf-ffi/cbindgen.toml leaf-ffi/src/lib.rs > target/release/leaf.h

windows:
	cargo build -p leaf-ffi --release --target x86_64-pc-windows-msvc --no-default-features --features default-ring
	mkdir -p ../Fluters/windows/runner/libs/x64
	cp target/x86_64-pc-windows-msvc/release/leaf.lib ../Fluters/windows/runner/libs/x64/leaf.lib
	cbindgen --config leaf-ffi/cbindgen.toml leaf-ffi/src/lib.rs > target/x86_64-pc-windows-msvc/release/leaf.h
	cp target/x86_64-pc-windows-msvc/release/leaf.h ../Fluters/windows/runner/leaf.h

android:
	cargo ndk -t armeabi-v7a -t x86 -t x86_64 -t arm64-v8a build --release -p leaf-android
lib-dev:
	cargo build -p leaf-ffi
	cbindgen --config leaf-ffi/cbindgen.toml leaf-ffi/src/lib.rs > target/debug/leaf.h

local:
	cargo build -p leaf-bin --release

local-dev:
	cargo build -p leaf-bin

mipsel:
	./misc/build_cross.sh mipsel-unknown-linux-musl

mips:
	./misc/build_cross.sh mips-unknown-linux-musl

test:
	cargo test -p leaf -- --nocapture

# Force a re-generation of protobuf files.
proto-gen:
	touch leaf/build.rs
	PROTO_GEN=1 cargo build -p leaf
