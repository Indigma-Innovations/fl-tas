"""
End-to-end test for TAS /v1/test-aggregate

What it does:
1) GET /v1/public-key
2) Create two vectors
3) Compute plaintext average locally
4) Encrypt each vector as JSON array using libsodium sealed box (via PyNaCl)
5) POST /v1/test-aggregate with base64 ciphertexts and op="mean"
6) Compare server result with local plaintext average (within tolerance)
"""

import base64
import json
import math
from typing import List

import httpx
from nacl.public import PublicKey, SealedBox


def mean_vec(a: List[float], b: List[float]) -> List[float]:
    if len(a) != len(b):
        raise ValueError("dimension mismatch")
    return [(x + y) / 2.0 for x, y in zip(a, b)]


def almost_equal_vec(a: List[float], b: List[float], tol: float = 1e-9) -> bool:
    if len(a) != len(b):
        return False
    for x, y in zip(a, b):
        if not math.isfinite(x) or not math.isfinite(y):
            return False
        if abs(x - y) > tol:
            return False
    return True


def main() -> None:
    base_url = "http://127.0.0.1:9000"
    timeout = httpx.Timeout(10.0)

    # 1) Fetch raw public key bytes (32 bytes for X25519)
    pk_bytes = httpx.get(f"{base_url}/v1/public-key", timeout=timeout).content
    print("Public key bytes (base64):", base64.b64encode(pk_bytes).decode("ascii"))
    if len(pk_bytes) != 32:
        raise RuntimeError(
            f"Unexpected public key length: {len(pk_bytes)} (expected 32)"
        )

    pk = PublicKey(pk_bytes)
    sealed_box = SealedBox(pk)

    # 2) Create vectors
    v1 = [1.0, 2.0, 3.0, 4.0]
    v2 = [10.0, 20.0, 30.0, 40.0]
    print(f"Plain vectors:\nv1 = {v1}\nv2 = {v2}")

    # 3) Plain average
    expected = mean_vec(v1, v2)

    # 4) Encrypt each vector as UTF-8 JSON array
    def encrypt_vec(v: List[float]) -> str:
        plaintext = json.dumps(v, separators=(",", ":")).encode("utf-8")
        ct = sealed_box.encrypt(plaintext)  # sealed box ciphertext bytes
        return base64.b64encode(ct).decode("ascii")

    ct1_b64 = encrypt_vec(v1)
    ct2_b64 = encrypt_vec(v2)
    print(f"Encrypted vectors (base64):\nct1 = {ct1_b64}\nct2 = {ct2_b64}")

    # 5) Ask TAS to aggregate (mean)
    payload = {
        "op": "mean",
        "ciphertexts": [ct1_b64, ct2_b64],
        "max_dim": 100000,
    }

    r = httpx.post(f"{base_url}/v1/test-aggregate", json=payload, timeout=timeout)
    r.raise_for_status()
    data = r.json()

    # 6) Validate
    result = data.get("result")
    if not isinstance(result, list):
        raise RuntimeError(f"Unexpected response: {data}")

    ok = almost_equal_vec(expected, [float(x) for x in result], tol=1e-9)

    print("---- TAS test-aggregate ----")
    print("Expected (plain mean):", expected)
    print("Server response:", data)
    print("PASS" if ok else "FAIL")

    if not ok:
        raise SystemExit(2)


if __name__ == "__main__":
    main()
