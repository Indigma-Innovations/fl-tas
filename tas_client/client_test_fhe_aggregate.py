import base64
import io
import math
import os
import tempfile
from typing import List, Any

import httpx
from tenseal import sealapi as seal


def mean_vec(a: List[float], b: List[float]) -> List[float]:
    if len(a) != len(b):
        raise ValueError("dimension mismatch")
    return [(x + y) / 2.0 for x, y in zip(a, b)]


def almost_equal_vec(a: List[float], b: List[float], tol: float) -> bool:
    if len(a) != len(b):
        return False
    for x, y in zip(a, b):
        if not math.isfinite(x) or not math.isfinite(y):
            return False
        if abs(x - y) > tol:
            return False
    return True


def vec_errors(expected: List[float], got: List[float]) -> List[dict]:
    out = []
    for i, (e, g) in enumerate(zip(expected, got)):
        abs_err = abs(g - e)
        rel_err = abs_err / (abs(e) + 1e-12)
        out.append(
            {"i": i, "expected": e, "got": g, "abs_err": abs_err, "rel_err": rel_err}
        )
    return out


def print_vec_error_report(
    expected: List[float], got: List[float], tol: float, top_k: int = 8
) -> None:
    errs = vec_errors(expected, got)
    errs.sort(key=lambda d: d["abs_err"], reverse=True)

    max_abs = errs[0]["abs_err"] if errs else 0.0
    max_rel = errs[0]["rel_err"] if errs else 0.0

    print("---- error report ----")
    print("tol:", tol)
    print("max_abs_err:", max_abs)
    print("max_rel_err:", max_rel)


def _ckks_scheme_value() -> Any:
    """
    TenSEAL sealapi exposure differs per build.
    Try common enum containers + both CKKS/ckks members.
    Fall back to CKKS=2 (SEAL's scheme_type::ckks).
    """
    # Prefer TenSEAL-style: seal.SCHEME_TYPE.CKKS
    st = getattr(seal, "SCHEME_TYPE", None)
    if st is not None:
        if hasattr(st, "CKKS"):
            return st.CKKS
        if hasattr(st, "ckks"):
            return st.ckks

    # SEAL-style: seal.scheme_type.ckks
    st = getattr(seal, "scheme_type", None)
    if st is not None:
        if hasattr(st, "ckks"):
            return st.ckks
        if hasattr(st, "CKKS"):
            return st.CKKS

    # Other occasional names
    for name in ("SchemeType", "scheme", "SCHEME_TYPE"):
        obj = getattr(seal, name, None)
        if obj is not None:
            if hasattr(obj, "CKKS"):
                return getattr(obj, "CKKS")
            if hasattr(obj, "ckks"):
                return getattr(obj, "ckks")

    return 2  # Microsoft SEAL: scheme_type::ckks == 2


def _sec_level_value() -> Any:
    """
    Prefer TC128 if available, else NONE/none.
    Tries both SEC_LEVEL_TYPE and sec_level_type containers and both
    TC128/tc128 + NONE/none members.
    """
    for enum_name in (
        "SEC_LEVEL_TYPE",
        "sec_level_type",
        "SecLevelType",
        "sec_level",
        "SEC_LEVEL_TYPE",
    ):
        enum_obj = getattr(seal, enum_name, None)
        if enum_obj is None:
            continue

        for member in ("TC128", "tc128"):
            if hasattr(enum_obj, member):
                return getattr(enum_obj, member)

        for member in ("NONE", "none"):
            if hasattr(enum_obj, member):
                return getattr(enum_obj, member)

    raise RuntimeError(
        "Cannot find SEC_LEVEL_TYPE / sec_level_type in tenseal.sealapi. "
        "Try printing: dir(seal) and then dir(seal.SEC_LEVEL_TYPE) if present."
    )


def load_parms(parms_bytes: bytes) -> Any:
    ckks = _ckks_scheme_value()
    parms = seal.EncryptionParameters(ckks)

    # parms.load(path: str)
    _load_from_bytes_via_tempfile(parms.load, parms_bytes, suffix=".parms.bin")
    return parms


def make_context(parms: Any) -> Any:
    sec = _sec_level_value()
    try:
        return seal.SEALContext(parms, True, sec)
    except TypeError:
        # some bindings omit the security-level parameter
        return seal.SEALContext(parms, True)


def _load_from_bytes_via_tempfile(load_fn, data: bytes, suffix: str) -> Any:
    """
    Some TenSEAL sealapi builds only support .load(path: str).
    This helper writes bytes to a temp file and calls load_fn(path).
    """
    fd, path = tempfile.mkstemp(suffix=suffix)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        return load_fn(path)
    finally:
        try:
            os.remove(path)
        except OSError:
            pass


def load_public_key(ctx: Any, pk_bytes: bytes) -> Any:
    pk = seal.PublicKey()

    # Try stream-style first (some builds support it)
    try:
        pk.load(ctx, io.BytesIO(pk_bytes))
        return pk
    except TypeError:
        pass
    except Exception:
        pass

    # Fallback: file-path style load (common in some TenSEAL builds)
    def _load_pk_from_path(path: str) -> None:
        # Some builds: pk.load(ctx, path)
        return pk.load(ctx, path)

    _load_from_bytes_via_tempfile(_load_pk_from_path, pk_bytes, suffix=".pk.bin")
    return pk


def encode_vector(ctx: Any, v: List[float], scale: float) -> Any:
    encoder = seal.CKKSEncoder(ctx)
    pt = seal.Plaintext()

    # Different bindings expose different signatures.
    # Try: encode(v, scale, pt) then fallback to encode(v, scale) returning Plaintext.
    try:
        encoder.encode(v, scale, pt)
        return pt
    except Exception:
        return encoder.encode(v, scale)


def encode_scalar(ctx: Any, x: float, scale: float) -> Any:
    encoder = seal.CKKSEncoder(ctx)
    pt = seal.Plaintext()
    try:
        encoder.encode(x, scale, pt)
        return pt
    except Exception:
        return encoder.encode(x, scale)


def encrypt_plain(ctx: Any, pk: Any, pt: Any) -> Any:
    encryptor = seal.Encryptor(ctx, pk)
    ct = seal.Ciphertext()
    try:
        encryptor.encrypt(pt, ct)
        return ct
    except Exception:
        return encryptor.encrypt(pt)


def ct_get_scale(ct: Any) -> float:
    # Some bindings use .scale() method, others .scale attribute
    try:
        return float(ct.scale())
    except Exception:
        return float(ct.scale)


def ct_set_scale(ct: Any, s: float) -> None:
    # Some bindings use set_scale, others expose mutable scale
    try:
        ct.set_scale(float(s))
        return
    except Exception:
        pass
    try:
        ct.scale = float(s)
    except Exception:
        pass


def serialize_ciphertext(ct: Any) -> bytes:
    """
    This TenSEAL build exposes Ciphertext.save(path: str) only.
    Serialize by saving to a temp file and reading it back.
    """
    fd, path = tempfile.mkstemp(suffix=".ct.bin")
    try:
        os.close(fd)  # we will let SEAL write to the path
        ct.save(path)  # <-- path string, not BytesIO
        with open(path, "rb") as f:
            return f.read()
    finally:
        try:
            os.remove(path)
        except OSError:
            pass


def evaluator_add(ctx: Any, a: Any, b: Any) -> Any:
    ev = seal.Evaluator(ctx)
    out = seal.Ciphertext()
    try:
        ev.add(a, b, out)
        return out
    except Exception:
        return ev.add(a, b)


def evaluator_multiply_plain_inplace(ctx: Any, ct: Any, pt: Any) -> Any:
    ev = seal.Evaluator(ctx)
    try:
        ev.multiply_plain_inplace(ct, pt)
        return ct
    except Exception:
        out = seal.Ciphertext()
        ev.multiply_plain(ct, pt, out)
        return out


def evaluator_rescale_to_next_inplace(ctx: Any, ct: Any) -> Any:
    ev = seal.Evaluator(ctx)
    try:
        ev.rescale_to_next_inplace(ct)
        return ct
    except Exception:
        # Some builds don’t expose rescale, allow test to continue (less accurate).
        return ct


def main() -> None:
    base_url = "http://127.0.0.1:9000"
    timeout = httpx.Timeout(120.0)

    # 1) fetch key-info
    key_info = httpx.get(f"{base_url}/v1/fhe/key-info", timeout=timeout).json()
    key_hash = key_info["key_hash"]
    scale_bits = int(key_info["params"]["scale_bits"])
    print("key_hash:", key_hash, "scale_bits:", scale_bits)

    # 2) fetch blobs needed for encryption
    parms_bytes = httpx.get(f"{base_url}/v1/fhe/blobs/params", timeout=timeout).content
    pk_bytes = httpx.get(f"{base_url}/v1/fhe/blobs/public_key", timeout=timeout).content

    # 3) build context + load pk
    parms = load_parms(parms_bytes)
    ctx = make_context(parms)
    pk = load_public_key(ctx, pk_bytes)

    # 4) vectors
    v1 = [1.0, 2.0, 3.0, 4.0]
    v2 = [10.0, 20.0, 30.0, 40.0]
    expected = mean_vec(v1, v2)

    # 5) encrypt both at scale 2^scale_bits
    scale = float(2**scale_bits)
    pt1 = encode_vector(ctx, v1, scale)
    pt2 = encode_vector(ctx, v2, scale)
    ct1 = encrypt_plain(ctx, pk, pt1)
    ct2 = encrypt_plain(ctx, pk, pt2)

    # 6) homomorphic mean: (ct1 + ct2) * 0.5, with rescale
    ct_sum = evaluator_add(ctx, ct1, ct2)

    # IMPORTANT: encode scalar 0.5 at same scale as ct_sum to keep CKKS consistent,
    # then rescale after multiply_plain.
    sum_scale = ct_get_scale(ct_sum)
    pt_half = encode_scalar(ctx, 0.5, sum_scale)

    ct_mean = evaluator_multiply_plain_inplace(ctx, ct_sum, pt_half)
    ct_mean = evaluator_rescale_to_next_inplace(ctx, ct_mean)

    # Optional: try to reset scale to a nice value
    ct_set_scale(ct_mean, scale)

    ct_b64 = base64.b64encode(serialize_ciphertext(ct_mean)).decode("ascii")

    # 7) send to server for decryption
    payload = {
        "key_hash": key_hash,
        "ciphertext_b64": ct_b64,
        "expected_vector_len": 0,
    }
    r = httpx.post(f"{base_url}/v1/fhe/decrypt", json=payload, timeout=timeout)
    if r.status_code != 200:
        print("status:", r.status_code)
        print("body:", r.text)
        raise SystemExit(1)
    data = r.json()

    got_full = [float(x) for x in data["plaintext_vector"]]
    got = got_full[: len(expected)]

    # CKKS is approximate -> tolerance depends on parms; start loose.
    tol = 1e-2
    ok = almost_equal_vec(expected, got, tol=tol)

    print("---- FHE decrypt mean test ----")
    print("Expected:", expected)
    print("Got     :", got)
    print("tol     :", tol)
    print("PASS" if ok else "FAIL")

    print_vec_error_report(expected, got, tol=tol, top_k=8)

    if ok:
        print("PASS")
    else:
        print("FAIL")
        raise SystemExit(2)


if __name__ == "__main__":
    main()
