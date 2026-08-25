#include <cstring>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <vector>
#include <openssl/sha.h>
#include <sodium.h>
#include "tas_types.hpp"

static std::string to_hex(const unsigned char* data, size_t len) {
  static const char* h = "0123456789abcdef";
  std::string out; out.reserve(len*2);
  for (size_t i=0;i<len;i++){ out.push_back(h[data[i]>>4]); out.push_back(h[data[i]&0xF]); }
  return out;
}

static std::string b64(const std::vector<unsigned char>& data) {
  const size_t maxlen = sodium_base64_encoded_len(data.size(), sodium_base64_VARIANT_ORIGINAL);
  std::string out(maxlen, '\0');
  sodium_bin2base64(out.data(), out.size(), data.data(), data.size(), sodium_base64_VARIANT_ORIGINAL);
  out.resize(std::strlen(out.c_str()));
  return out;
}

TasKeyInfo load_or_create_keys(const std::string& root);
TasKeyInfo load_or_create_keys(const std::string& root) {
  std::filesystem::create_directories(root + "/keys");
  const auto pub_path = root + "/keys/public.key";
  const auto sec_path = root + "/keys/secret.key";
  TasKeyInfo info{};
  info.public_key.resize(crypto_box_PUBLICKEYBYTES);
  info.secret_key.resize(crypto_box_SECRETKEYBYTES);
  if (std::filesystem::exists(pub_path) && std::filesystem::exists(sec_path)) {
    std::ifstream p(pub_path, std::ios::binary); p.read((char*)info.public_key.data(), info.public_key.size());
    std::ifstream s(sec_path, std::ios::binary); s.read((char*)info.secret_key.data(), info.secret_key.size());
  } else {
    crypto_box_keypair(info.public_key.data(), info.secret_key.data());
    std::ofstream p(pub_path, std::ios::binary); p.write((char*)info.public_key.data(), info.public_key.size());
    std::ofstream s(sec_path, std::ios::binary); s.write((char*)info.secret_key.data(), info.secret_key.size());
  }
  unsigned char digest[SHA256_DIGEST_LENGTH];
  SHA256(info.public_key.data(), info.public_key.size(), digest);
  info.public_key_hash = to_hex(digest, SHA256_DIGEST_LENGTH);
  info.key_id = info.public_key_hash;
  info.public_key_b64 = b64(info.public_key);
  info.created_at = "startup";
  return info;
}
