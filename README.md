# Trusted Aggregation Service (TAS)

A C++/Python TAS service for averaging models using FedAvg.

Modes:
- Plaintext aggregation (X25519) - default. Uses libsodium sealed boxes (public key encryption). In this mode, clients are expected to encrypt their model updates using the TAS public key, send the encrypted payload to a federated orchestrator, the federated orchestrator upon readiness of aggregation will send the encrypted payloads to TAS, TAS will decrypt and aggregate the updates and return the aggregated model to the federated orchestrator.
- Fully Homomorphic Encryption (FHE) aggregation (CKKS via Microsoft SEAL) - optional, requires TAS_ENABLE_SEAL=ON at build time. Uses Microsoft SEAL CKKS homomorphic encryption. In this mode, clients are expected to encrypt their model updates using the TAS FHE public key, send the encrypted payload to a federated orchestrator, the federated orchestrator upon readiness of aggregation will perform FedAvg on the encrypted payloads and send the aggregated ciphertext to TAS, TAS will decrypt and return the aggregated model to the federated orchestrator.

## Dependencies

TAS has both system-level dependencies for the C++ server and Python dependencies used by the aggregation helper and test clients.

### Python dependencies

The core Python dependencies required by the TAS Python aggregation helper used during  aggregation:
- `numpy`
- `safetensors`
- `torch`

TAS currently uses the Python helper `tas_helper.aggregate` to perform weighted FedAvg.

Install the project dependencies with:

```bash
uv sync
```

### Development and test dependencies

The test clients under `tas_client/` require additional Python packages:
- `httpx` 
- `pynacl`
- `tenseal`

Install both the project and development dependencies with:

```bash
uv sync --dev
```

The development dependencies are required to run the TAS test clients:

```bash
uv run tas_client/client_test_aggregate.py
uv run tas_client/client_test_fhe_aggregate.py
```

The FHE test client additionally requires the TAS server to be built with Microsoft SEAL support using `TAS_ENABLE_SEAL=ON`.

### System dependencies

The C++ TAS server requires the following system packages on Ubuntu/Debian:

```bash
sudo apt update
sudo apt install -y \
    build-essential \
    cmake \
    pkg-config \
    libsodium-dev \
    libssl-dev \
    libcurl4-openssl-dev \
    libasio-dev \
    nlohmann-json3-dev
```

Microsoft SEAL is additionally required when building TAS with FHE support.

## Run locally

1) Install system dependencies

2) Build TAS server
```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
```

To build the TAS server with SEAL enabled:
```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DTAS_ENABLE_SEAL=ON
cmake --build build -j
```

3) Run TAS server
```bash
export TAS_DATA_DIR="$(pwd)/.tasdata"
# Allow all POSTs for local dev:
unset TAS_ALLOWED_ORCH_IP
./build/tas_server
```

To restrict POST endpoints to a specific IP:
```text
export TAS_ALLOWED_ORCH_IP=127.0.0.1
./build/tas_server
```

4) Test the TAS server
```bash
curl -s http://127.0.0.1:9000/v1/health
curl -s http://127.0.0.1:9000/v1/key-info | head
```

You can also open the API docs in a browser
- Swagger UI: http://127.0.0.1:9000/docs
- OpenAPI spec: http://127.0.0.1:9000/spec/openapi.yaml

5) Run the test aggregate client
```bash
uv run tas_client/client_test_aggregate.py
```

### Test FHE decrypt

```bash
uv run tas_client/client_test_fhe_aggregate.py
```

## Run via Docker
```bash
docker build -t fedmaestro-tas .
docker run --rm -p 9000:9000 -e TAS_DATA_DIR=/var/lib/tas -v $(pwd)/data:/var/lib/tas fedmaestro-tas
```

## Clean rebuild and local runtime data

After building and testing TAS locally, you may want to remove generated build artifacts or runtime data before rebuilding.

### Clean C++ rebuild

The `build/` directory contains CMake and compiled build artifacts.

It is safe to remove when you want a completely clean rebuild:

```bash
rm -rf build
```

Then rebuild TAS:
```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
```

For an FHE build, add `-DTAS_ENABLE_SEAL=ON` to the cmake command.

### Clean runtime data
The `TAS_DATA_DIR` directory contains runtime data (keys, session buffers, etc.) and can be removed to reset the TAS server state. For example:
- X25519 keypair under .tasdata/keys
- SEAL/CKKS keys under .tasdata/fhe_keys when FHE is enabled
- Other TAS session/runtime data

To completely reset the local TAS instance:
```bash
rm -rf .tasdata
```

On the next startup, TAS will generate new cryptographic keys.

## Public-key Cryptography (X25519)
- Generates/persists a long-term X25519 keypair in `TAS_DATA_DIR/keys`.
- Exposes:
  - GET `/v1/health` (public) - basic health check
  - GET `/v1/key-info` (public) - key metadata (hash, id, algorithm)
  - GET `/v1/public-key` (public) - raw public key bytes
  - POST `/v1/test-aggregate` (public) - decrypts encrypted vectors and returns plaintext aggregation (sum/mean) for testing
- Supports session endpoints (POST endpoints can be restricted by IP via TAS_ALLOWED_ORCH_IP):
  - POST `/v1/sessions`
  - POST `/v1/sessions/{id}/inputs`
  - POST `/v1/sessions/{id}/finalize`
  - GET `/v1/sessions/{id}/summary`
- Accepts ciphertext input references, downloads + decrypts sealed box payloads.
- Buffers plaintext safetensors files per session.
- Finalizes using Python helper (`tas_helper.aggregate`) for weighted FedAvg.
- Generates/persists SEAL CKKS keys in `TAS_DATA_DIR/fhe_keys` when SEAL is enabled.


## FHE (CKKS via Microsoft SEAL) - when built with TAS_ENABLE_SEAL

When compiled with `-DTAS_ENABLE_SEAL=ON`, TAS also exposes FHE endpoints:

- GET `/v1/fhe/key-info` (public) - CKKS parameters and key hash
- GET `/v1/fhe/blobs/{public_key|relin_keys|galois_keys|params}` (public) - binary blobs
- POST `/v1/fhe/decrypt` (restricted by TAS_ALLOWED_ORCH_IP) - decrypts a CKKS ciphertext and returns decoded slots

Note: CKKS decoding returns all slots by default (`poly_modulus_degree/2`).
If you request a logical vector length, TAS can truncate the decoded vector to that length.

## Limitations
This MVP uses an internal Python aggregation helper in container. This can be replaced by native safetensors aggregation later.

>Note: To start TAS with different FHE parameters, you can set the following environment variables before starting the server:
```bash
export TAS_DATA_DIR="$PWD/.tasdata-fhe-32768"
export TAS_FHE_POLY_MODULUS_DEGREE=32768
export TAS_FHE_COEFF_MODULUS_BITS=60,40,40,60
export TAS_FHE_SCALE_BITS=40
./build/tas_server
```

## Funding and Acknowledgements

This work has been co-funded through the **O-CEI (Open Cloud-Edge-IoT Platform Uptake in Large Scale Cross-Domain Pilots)** project, funded by the European Union's Horizon Europe programme under Grant Agreement No. **101189589**.

The Trusted Aggregation Service (TAS) is developed by **[Indigma Innovations](https://indigma.eu)** and is intended to integrate with the **[ARIEL](https://indigma.eu/ariel/)** federated learning implementation developed by Indigma Innovations, funded by O-CEI Open Call 1. ARIEL provides privacy-preserving federated AI orchestration and is powered by Indigma's **[FedMaestro](https://indigma.eu/fedmaestro/)** federated learning orchestrator.

TAS provides the secure aggregation component used by the federated learning architecture, supporting both public-key encrypted aggregation and Fully Homomorphic Encryption (FHE) based aggregation.

Any views and opinions expressed in this software or its documentation are those of the authors and do not necessarily represent those of the European Union. Neither the European Union nor the granting authority can be held responsible for them.

## License

This project is licensed under the **Apache License 2.0**.

See the [`LICENSE`](LICENSE) file for the full license text.

Copyright © 2026 Indigma Innovations.
