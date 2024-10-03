# kyberlib

![divider][divider]

## Overview 📖

KyberLib is a robust Rust library designed for **CRYSTALS-Kyber Post-Quantum Cryptography**, offering strong security guarantees. This library is compatible with `no_std`, making it suitable for embedded devices and avoids memory allocations. Additionally, it contains reference implementations with no unsafe code and provides an optimized AVX2 version by default on x86_64 platforms. You can also compile it to WebAssembly (WASM) using wasm-bindgen.

## Features ✨

### Core Features

- **`no_std` compatible**: No dependence on the Rust standard library
- **Avoid allocations**: Uses stack-based data structures only
- **Configurable**: Features to enable different parameter sets
- **Optimised x86_64**: Uses assembly for performance-critical code, including an optimised AVX2 version by default.
- **Safe code**: Reference implementations have no `unsafe` blocks
- **WebAssembly Support**: Can be compiled to WASM using wasm-bindgen.

### Advanced Features

- **Allocation-free Guarantee**: KyberLib guarantees all its core cryptography operations are free of heap allocations.
- **Assembly Optimizations**: The x86_64 assembly implementations use AVX2 instructions for high performance.
- **Security**: KyberLib contains no unsafe code in its public API surface.

## Functionality 📚

- **Key Generation**: Create public/private key pairs
- **Encapsulation**: Encapsulate a shared secret with a public key
- **Decapsulation**: Decapsulate a shared secret with a private key
- **Key Exchange**: Perform authenticated key exchanges

See [Documentation][08] for full API details.

## Getting Started 🚀

It takes just a few minutes to get up and running with `kyberlib`.

### Requirements

The minimum supported Rust toolchain version is currently Rust
**1.60** or later (stable).

### Installation

To install `kyberlib`, you need to have the Rust toolchain installed on
your machine. You can install the Rust toolchain by following the
instructions on the [Rust website][13].

Once you have the Rust toolchain installed, you can install `kyberlib`
using the following command:

```shell
cargo install kyberlib
```

## Usage 📖

To use the `kyberlib` library in your project, add the following to your
`Cargo.toml` file:

```toml
[dependencies]
kyberlib = "0.0.6"
```

Add the following to your `main.rs` file:

```rust
extern crate kyberlib;
use kyberlib::*;
```

then you can use the functions in your application code.

For optimisations on x86 platforms enable the `avx2` feature and the following RUSTFLAGS:

```shell
export RUSTFLAGS="-C target-feature=+aes,+avx2,+sse2,+sse4.1,+bmi2,+popcnt"
```

## Crate Features 📦

### Key Encapsulation

```rust
// Generate Keypair
let keys_bob = keypair(&mut rng)?;

// Alice encapsulates a shared secret using Bob's public key
let (ciphertext, shared_secret_alice) = encapsulate(&keys_bob.public, &mut rng)?;

// Bob decapsulates a shared secret using the ciphertext sent by Alice
let shared_secret_bob = decapsulate(&ciphertext, &keys_bob.secret)?;

assert_eq!(shared_secret_alice, shared_secret_bob);
```

### Unilaterally Authenticated Key Exchange

```rust
let mut rng = rand::thread_rng();

// Initialize the key exchange structs
let mut alice = Uake::new();
let mut bob = Uake::new();

// Generate Bob's Keypair
let bob_keys = keypair(&mut rng)?;

// Alice initiates key exchange
let client_init = alice.client_init(&bob_keys.public, &mut rng)?;

// Bob authenticates and responds
let server_response = bob.server_receive(
  client_init, &bob_keys.secret, &mut rng
)?;

// Alice decapsulates the shared secret
alice.client_confirm(server_response)?;

// Both key exchange structs now have the same shared secret
assert_eq!(alice.shared_secret, bob.shared_secret);
```

### Mutually Authenticated Key Exchange

Follows the same workflow except Bob requires Alice's public keys:

```rust
let mut alice = Ake::new();
let mut bob = Ake::new();

let alice_keys = keypair(&mut rng)?;
let bob_keys = keypair(&mut rng)?;

let client_init = alice.client_init(&bob_keys.public, &mut rng)?;

let server_response = bob.server_receive(
  client_init, &alice_keys.public, &bob_keys.secret, &mut rng
)?;

alice.client_confirm(server_response, &alice_keys.secret)?;

assert_eq!(alice.shared_secret, bob.shared_secret);
```

## Macros 🦀

The KyberLib crate provides several macros to simplify common cryptographic operations:

- [`kyberlib_generate_key_pair!`](https://docs.rs/kyberlib/latest/kyberlib/macro.kyberlib_generate_key_pair.html): Generates a public and private key pair for CCA-secure Kyber key encapsulation mechanism.

- [`kyberlib_encrypt_message!`](https://docs.rs/kyberlib/latest/kyberlib/macro.kyberlib_encrypt_message.html): Generates cipher text and a shared secret for a given public key.

- [`kyberlib_decrypt_message!`](https://docs.rs/kyberlib/latest/kyberlib/macro.kyberlib_decrypt_message.html): Generates a shared secret for a given cipher text and private key.

- [`kyberlib_uake_client_init!`](https://docs.rs/kyberlib/latest/kyberlib/macro.kyberlib_uake_client_init.html): Initiates a Unilaterally Authenticated Key Exchange.

- [`kyberlib_uake_server_receive!`](https://docs.rs/kyberlib/latest/kyberlib/macro.kyberlib_uake_server_receive.html): Handles the output of a `kyberlib_uake_client_init()` request.

- [`kyberlib_uake_client_confirm!`](https://docs.rs/kyberlib/latest/kyberlib/macro.kyberlib_uake_client_confirm.html): Decapsulates and authenticates the shared secret from the output of `kyberlib_uake_server_receive()`.

- [`kyberlib_ake_client_init!`](https://docs.rs/kyberlib/latest/kyberlib/macro.kyberlib_ake_client_init.html): Initiates a Mutually Authenticated Key Exchange.

- [`kyberlib_ake_server_receive!`](https://docs.rs/kyberlib/latest/kyberlib/macro.kyberlib_uake_server_receive.html): Handles and authenticates the output of a `kyberlib_ake_client_init()` request.

- [`kyberlib_ake_client_confirm!`](https://docs.rs/kyberlib/latest/kyberlib/macro.kyberlib_ake_client_confirm.html): Decapsulates and authenticates the shared secret from the output of `kyberlib_ake_server_receive()`.

See the [macros module documentation](https://docs.rs/kyberlib/latest/kyberlib/index.html#macros) for more details and usage examples.

## Errors

The KyberLibError enum has two variants:

- **InvalidInput** - One or more inputs to a function are incorrectly sized. A possible cause of this is two parties using different security levels while trying to negotiate a key exchange.
- **InvalidKey** - Error when generating keys.
- **Decapsulation** - The ciphertext was unable to be authenticated. The shared secret was not decapsulated.
- **RandomBytesGeneration** - Error trying to fill random bytes (i.e., external (hardware) RNG modules can fail).

## Examples

To get started with `kyberlib`, you can use the examples provided in the
`examples` directory of the project.

To run the examples, clone the repository and run the following command
in your terminal from the project root directory.

### Example 1: Implements an authenticated key exchange protocol

Alice and Bob exchange public keys to derive a shared secret in a way that authenticates each party.

Run the following command in your terminal from the project root directory.

```shell
cargo run --example ake
```

### Example 2: Demonstrates key encapsulation and decapsulation

Alice generates a keypair. Bob encapsulates a secret using Alice's public key. Alice decapsulates the secret using her private key. This allows secure communication.

Run the following command in your terminal from the project root directory.

```shell
cargo run --example kem
```

### Example 3: Implements an unauthenticated key exchange protocol

Alice and Bob exchange public information to derive a shared secret without authenticating each other. Provides confidentiality but not authentication.

Run the following command in your terminal from the project root directory.

```shell
cargo run --example uake
```

### Platform support

`kyberlib` supports a variety of CPU architectures. It is supported and tested on MacOS, Linux, and Windows.

### Documentation

**Info:** Please check out our [website][00] for more information. You can find our documentation on [docs.rs][08], [lib.rs][09] and
[crates.io][07].

## Semantic Versioning Policy 🚥

For transparency into our release cycle and in striving to maintain
backward compatibility, `kyberlib` follows [semantic versioning][06].

## License 📝

KyberLib is distributed under the terms of both the MIT license and the
Apache License (Version 2.0).

See [LICENSE-APACHE][01] and [LICENSE-MIT][02] for details.

