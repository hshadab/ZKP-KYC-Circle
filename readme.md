# ZKP-KYC-Circle

A zero-knowledge proof system for Circle's KYC verification webhook.

## Overview

This project demonstrates a zero-knowledge cryptography application for validating Know Your Customer (KYC) information privately. It uses zkEngine, a zkWASM virtual machine that enables zero-knowledge proofs for arbitrary WASM programs.

The system allows proving that:
1. A user possesses a valid wallet address
2. The user has passed KYC verification
3. The signature verification is valid

All without revealing the actual wallet address or KYC information to verifiers.

## Architecture

The project consists of these components:

- **zkEngine_dev**: Core zkWASM virtual machine based on Nova (Arecibo/Hypernova IVC)
- **kyc_prover**: Rust CLI wrapper for generating proofs
- **kyc_wasm**: WebAssembly guest program for KYC validation
- **zk_server**: HTTP API server for proof generation

## How It Works

The system leverages the following cryptographic process:

1. The prover provides a wallet address and KYC approval flags
2. The wallet address is hashed using Keccak-256 to create a commitment
3. A zero-knowledge proof is generated showing the hash is valid and KYC approval exists
4. The verifier can confirm KYC approval without seeing the actual wallet address

## Technical Details

- **Proof System**: Nova recursive SNARKs with Hypernova IVC optimization
- **Hash Function**: Keccak-256 (Ethereum compatible)
- **WASM VM**: Custom zkWASM implementation with Rust/Wasmi
- **Proving Time**: Configurable with step size parameter

## Getting Started

### Prerequisites

- Rust 1.70+
- Cargo
- Git

### Installation

```bash
# Clone the repository
git clone https://github.com/hshadab/ZKP-KYC-Circle
cd ZKP-KYC-Circle

# Build the project
cargo build --release
```

### Running the KYC Prover

```bash
# Generate a proof for a wallet with valid KYC
cargo run --bin kyc_host 0x742d35Cc6634C0532925a3b844Bc454e4438f44e 1 1

# Parameters:
# - Wallet address (Ethereum format)
# - KYC status (1 = approved)
# - Signature validity (1 = valid)
# - [Optional] Step size (default: 8)
```

### Running the API Server

```bash
# Start the HTTP API server
cargo run --bin zk_server

# The server will listen on http://0.0.0.0:8080
# You can send POST requests to /prove endpoint
```

Example API request:

```json
{
  "wallet": "0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
  "kyc": 1,
  "sig_valid": 1,
  "step": 8
}
```

## Repository Structure

```
ZKP-KYC-Circle/
├── zkEngine_dev/       # zkWASM VM core
│   ├── third-party/    # Dependencies (wasmi, etc.)
│   └── ...
├── kyc_prover/         # CLI KYC proof generator
│   └── src/
│       └── main.rs     # kyc_host.rs implementation
├── kyc_wasm/           # WebAssembly guest program
│   └── src/
│       └── lib.rs      # check_kyc implementation
├── zk_server/          # HTTP API server
│   └── src/
│       └── main.rs     # API implementation
└── Cargo.toml          # Workspace configuration
```

## Performance Metrics

Example proof generation metrics:
- Setup time: ~1-2 seconds
- Proving time: ~3-5 seconds (step size 8)
- Verification time: ~0.1 seconds
- Proof size: ~20-30 KB

Times may vary based on hardware and step size configuration.

## License

This project is licensed under either of
- Apache License, Version 2.0
- MIT license

at your option.

## Acknowledgments

Based on the zkEngine project from ICME-Lab: [https://github.com/ICME-Lab/zkEngine_dev/](https://github.com/ICME-Lab/zkEngine_dev/)
