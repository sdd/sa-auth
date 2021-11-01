yum install -y openssl openssl-devel

curl -l --output musl-1.2.2.tar.gz https://musl.libc.org/releases/musl-1.2.2.tar.gz
tar -xzvf musl-1.2.2.tar.gz
cd musl-1.2.2
./configure
make
make install
cp obj/musl-gcc /usr/bin/
cd ..

curl https://sh.rustup.rs -sSf | sh -s -- --profile default --default-toolchain nightly -y
source $HOME/.cargo/env
rustup target add x86_64-unknown-linux-musl

export OPENSSL_LIB_DIR=/lib64
export OPENSSL_INCLUDE_DIR=/usr/include
cargo build --release --target x86_64-unknown-linux-musl 