#pragma once
#include <string>
#include <vector>

struct TasKeyInfo {
  std::string key_id;
  std::string public_key_b64;
  std::string public_key_hash;
  std::string created_at;
  std::vector<unsigned char> public_key;
  std::vector<unsigned char> secret_key;
};
