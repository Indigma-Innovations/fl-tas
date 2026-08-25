#pragma once

#include <seal/seal.h>

#include <cstddef>
#include <memory>
#include <string>
#include <vector>

struct FheBlobMeta {
  std::string sha256;
  std::size_t size = 0;
};

struct FheKeyInfo {
  // High-level
  std::string scheme;
  std::string algorithm;
  std::string key_hash;
  int poly_modulus_degree;
  std::vector<int> coeff_modulus_bits;
  int scale_bits;
  std::string created_at;

  // Blob metadata (no huge base64 strings)
  FheBlobMeta public_key_blob;
  FheBlobMeta relin_keys_blob;
  FheBlobMeta galois_keys_blob;
  FheBlobMeta params_blob;

  // SEAL objects
  seal::EncryptionParameters params;
  std::shared_ptr<seal::SEALContext> context;
  seal::PublicKey public_key;
  seal::SecretKey secret_key;  // stays server-side only
  seal::RelinKeys relin_keys;
  seal::GaloisKeys galois_keys;

  FheKeyInfo();
};

FheKeyInfo load_or_create_fhe_keys(const std::string &root);

std::vector<double> decrypt_ckks_ciphertext(
    const FheKeyInfo &info,
    const std::vector<unsigned char> &ciphertext_bytes);
