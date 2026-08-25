#include "fhe_store.hpp"

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <openssl/sha.h>
#include <seal/seal.h>
#include <sstream>
#include <stdexcept>
#include <string>

#include <nlohmann/json.hpp>

// File helpers
static std::vector<unsigned char> read_bytes(const std::string &path) {
  std::ifstream f(path, std::ios::binary);
  if (!f) throw std::runtime_error("open_failed:" + path);
  return std::vector<unsigned char>((std::istreambuf_iterator<char>(f)),
                                    std::istreambuf_iterator<char>());
}

static void write_bytes(const std::string &path, const std::vector<unsigned char> &data) {
  std::ofstream f(path, std::ios::binary);
  if (!f) throw std::runtime_error("write_failed:" + path);
  f.write(reinterpret_cast<const char *>(data.data()),
          static_cast<std::streamsize>(data.size()));
  if (!f) throw std::runtime_error("write_failed:" + path);
}

template <typename T>
static std::vector<unsigned char> save_obj(const T &obj) {
  std::stringstream ss;
  obj.save(ss);
  const std::string s = ss.str();
  return std::vector<unsigned char>(s.begin(), s.end());
}

static std::vector<unsigned char> save_parms(const seal::EncryptionParameters &parms) {
  std::stringstream ss;
  parms.save(ss);
  const std::string s = ss.str();
  return std::vector<unsigned char>(s.begin(), s.end());
}

static std::string hex_sha256(const std::vector<unsigned char> &blob) {
  unsigned char digest[SHA256_DIGEST_LENGTH];
  SHA256(blob.data(), blob.size(), digest);

  static const char *h = "0123456789abcdef";
  std::string out;
  out.reserve(SHA256_DIGEST_LENGTH * 2);
  for (size_t i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
    out.push_back(h[digest[i] >> 4]);
    out.push_back(h[digest[i] & 0xF]);
  }
  return out;
}


static int env_int_or_default(const char *name, int default_value) {
  const char *raw = std::getenv(name);
  if (raw == nullptr || std::string(raw).empty()) return default_value;
  try {
    return std::stoi(raw);
  } catch (...) {
    throw std::runtime_error(std::string("invalid_env_int:") + name);
  }
}

static std::vector<int> env_int_list_or_default(
    const char *name, const std::vector<int> &default_value) {
  const char *raw = std::getenv(name);
  if (raw == nullptr || std::string(raw).empty()) return default_value;
  std::vector<int> out;
  std::stringstream ss(raw);
  std::string item;
  while (std::getline(ss, item, ',')) {
    if (item.empty()) continue;
    try {
      out.push_back(std::stoi(item));
    } catch (...) {
      throw std::runtime_error(std::string("invalid_env_int_list:") + name);
    }
  }
  if (out.empty()) throw std::runtime_error(std::string("empty_env_int_list:") + name);
  return out;
}

static bool is_power_of_two(int value) {
  return value > 0 && (value & (value - 1)) == 0;
}

static void validate_fhe_env_params(const FheKeyInfo &info) {
  if (!is_power_of_two(info.poly_modulus_degree) ||
      info.poly_modulus_degree < 1024) {
    throw std::runtime_error(
        "invalid TAS_FHE_POLY_MODULUS_DEGREE: expected a power of two >= 1024");
  }
  // Microsoft SEAL's built-in coefficient modulus tables stop at 32768. Larger
  // ARIEL models are handled by chunking multiple CKKS ciphertexts, not by using
  // unsupported polynomial modulus degrees such as 65536.
  if (info.poly_modulus_degree > 32768) {
    throw std::runtime_error(
        "unsupported TAS_FHE_POLY_MODULUS_DEGREE: maximum supported value is 32768; "
        "use client-side chunking for larger models");
  }
  if (info.scale_bits <= 0) {
    throw std::runtime_error(
        "invalid TAS_FHE_SCALE_BITS: expected a positive integer");
  }
}

static FheBlobMeta file_meta(const std::string &path) {
  auto bytes = read_bytes(path);
  FheBlobMeta m;
  m.size = bytes.size();
  m.sha256 = hex_sha256(bytes);
  return m;
}

//FheKeyInfo defaults

FheKeyInfo::FheKeyInfo()
    : scheme("ckks"),
      algorithm("ckks_seal_v1"),
      key_hash(""),
      poly_modulus_degree(8192),
      coeff_modulus_bits({60, 40, 40, 60}),
      scale_bits(40),
      created_at("startup"),
      params(seal::scheme_type::ckks),
      context(nullptr) {
  // Nothing heavy here; context is created later after parms are set.
}

// Load/Create keys
FheKeyInfo load_or_create_fhe_keys(const std::string &root) {
  FheKeyInfo info;

  const std::string dir = root + "/fhe_keys";
  std::filesystem::create_directories(dir);

  const std::string params_path = dir + "/params.bin";
  const std::string pub_path    = dir + "/public_key.bin";
  const std::string sec_path    = dir + "/secret_key.bin";
  const std::string relin_path  = dir + "/relin_keys.bin";
  const std::string galois_path = dir + "/galois_keys.bin";
  const std::string meta_path   = dir + "/meta.json";

  const bool exists =
      std::filesystem::exists(params_path) &&
      std::filesystem::exists(pub_path) &&
      std::filesystem::exists(sec_path) &&
      std::filesystem::exists(relin_path) &&
      std::filesystem::exists(galois_path);

  if (!exists) {
    info.poly_modulus_degree = env_int_or_default("TAS_FHE_POLY_MODULUS_DEGREE", info.poly_modulus_degree);
    info.coeff_modulus_bits = env_int_list_or_default("TAS_FHE_COEFF_MODULUS_BITS", info.coeff_modulus_bits);
    info.scale_bits = env_int_or_default("TAS_FHE_SCALE_BITS", info.scale_bits);
    validate_fhe_env_params(info);

    // Build parms
    info.params = seal::EncryptionParameters(seal::scheme_type::ckks);
    info.params.set_poly_modulus_degree(static_cast<size_t>(info.poly_modulus_degree));
    info.params.set_coeff_modulus(
        seal::CoeffModulus::Create(static_cast<size_t>(info.poly_modulus_degree),
                                   info.coeff_modulus_bits));

    // Context
    info.context = std::make_shared<seal::SEALContext>(info.params, true, seal::sec_level_type::none);
    if (!info.context->parameters_set()) {
      throw std::runtime_error(std::string("fhe_invalid_params: ") + info.context->parameter_error_message());
    }

    // Keys
    seal::KeyGenerator keygen(*info.context);
    info.secret_key = keygen.secret_key();
    keygen.create_public_key(info.public_key);
    keygen.create_relin_keys(info.relin_keys);
    keygen.create_galois_keys(info.galois_keys);

    // Serialize blobs
    const auto parms_bytes  = save_parms(info.params);
    const auto pub_bytes    = save_obj(info.public_key);
    const auto sec_bytes    = save_obj(info.secret_key);
    const auto relin_bytes  = save_obj(info.relin_keys);
    const auto galois_bytes = save_obj(info.galois_keys);

    // Persist
    write_bytes(params_path, parms_bytes);
    write_bytes(pub_path, pub_bytes);
    write_bytes(sec_path, sec_bytes);
    write_bytes(relin_path, relin_bytes);
    write_bytes(galois_path, galois_bytes);

    // Minimal meta
    nlohmann::json meta = {
        {"created_at", "startup"},
        {"poly_modulus_degree", info.poly_modulus_degree},
        {"coeff_modulus_bits", info.coeff_modulus_bits},
        {"scale_bits", info.scale_bits}
    };
    std::ofstream m(meta_path);
    if (!m) throw std::runtime_error("write_failed:" + meta_path);
    m << meta.dump(2);
  }

  // Load meta.json (optional)
  if (std::filesystem::exists(meta_path)) {
    auto meta = nlohmann::json::parse(std::ifstream(meta_path));
    info.created_at = meta.value("created_at", "startup");
    info.scale_bits = meta.value("scale_bits", info.scale_bits);
  } else {
    info.created_at = "startup";
  }

  // Load parms
  {
    auto bytes = read_bytes(params_path);
    std::stringstream ss;
    ss.write(reinterpret_cast<const char*>(bytes.data()),
             static_cast<std::streamsize>(bytes.size()));

    info.params = seal::EncryptionParameters(seal::scheme_type::ckks);
    info.params.load(ss);
  }

  // Recreate context from loaded parms
  info.context = std::make_shared<seal::SEALContext>(info.params, true, seal::sec_level_type::none);
  if (!info.context->parameters_set()) {
    throw std::runtime_error(
        std::string("fhe_invalid_params: ") +
        info.context->parameter_error_message());
  }

  // Load key objects using the context
  {
    auto bytes = read_bytes(pub_path);
    std::stringstream ss;
    ss.write(reinterpret_cast<const char*>(bytes.data()),
             static_cast<std::streamsize>(bytes.size()));
    info.public_key.load(*info.context, ss);
  }
  {
    auto bytes = read_bytes(sec_path);
    std::stringstream ss;
    ss.write(reinterpret_cast<const char*>(bytes.data()),
             static_cast<std::streamsize>(bytes.size()));
    info.secret_key.load(*info.context, ss);
  }
  {
    auto bytes = read_bytes(relin_path);
    std::stringstream ss;
    ss.write(reinterpret_cast<const char*>(bytes.data()),
             static_cast<std::streamsize>(bytes.size()));
    info.relin_keys.load(*info.context, ss);
  }
  {
    auto bytes = read_bytes(galois_path);
    std::stringstream ss;
    ss.write(reinterpret_cast<const char*>(bytes.data()),
             static_cast<std::streamsize>(bytes.size()));
    info.galois_keys.load(*info.context, ss);
  }

  // Fill numeric params in the struct (for key-info response)
  // These are derived from info.params but kept in fields for convenience.
  info.poly_modulus_degree = static_cast<int>(info.params.poly_modulus_degree());
  info.coeff_modulus_bits.clear();
  for (const auto &cm : info.params.coeff_modulus()) {
    info.coeff_modulus_bits.push_back(static_cast<int>(cm.bit_count()));
  }

  // Compute per-blob meta
  info.params_blob     = file_meta(params_path);
  info.public_key_blob = file_meta(pub_path);
  info.relin_keys_blob = file_meta(relin_path);
  info.galois_keys_blob= file_meta(galois_path);

  // Compute "key_hash" from public-ish material only (pub + relin + galois)
  {
    auto pub_bytes    = read_bytes(pub_path);
    auto relin_bytes  = read_bytes(relin_path);
    auto galois_bytes = read_bytes(galois_path);

    std::vector<unsigned char> digest_blob;
    digest_blob.reserve(pub_bytes.size() + relin_bytes.size() + galois_bytes.size());
    digest_blob.insert(digest_blob.end(), pub_bytes.begin(), pub_bytes.end());
    digest_blob.insert(digest_blob.end(), relin_bytes.begin(), relin_bytes.end());
    digest_blob.insert(digest_blob.end(), galois_bytes.begin(), galois_bytes.end());

    info.key_hash = hex_sha256(digest_blob);
  }

  return info;
}

// Decrypt helper

std::vector<double> decrypt_ckks_ciphertext(
    const FheKeyInfo &info,
    const std::vector<unsigned char> &ciphertext_bytes) {
  if (!info.context) throw std::runtime_error("missing_context");

  std::stringstream ct_stream;
  ct_stream.write(reinterpret_cast<const char*>(ciphertext_bytes.data()),
                  static_cast<std::streamsize>(ciphertext_bytes.size()));

  seal::Ciphertext ct;
  ct.load(*info.context, ct_stream);

  seal::Decryptor decryptor(*info.context, info.secret_key);
  seal::CKKSEncoder encoder(*info.context);

  seal::Plaintext pt;
  decryptor.decrypt(ct, pt);

  std::vector<double> result;
  encoder.decode(pt, result);
  return result;
}
