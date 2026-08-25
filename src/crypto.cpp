#include <sodium.h>
#include <stdexcept>
#include <vector>

std::vector<unsigned char> decrypt_sealed_box(
    const std::vector<unsigned char>& cipher,
    const std::vector<unsigned char>& pk,
    const std::vector<unsigned char>& sk) {
  if (cipher.size() < crypto_box_SEALBYTES) {
    throw std::runtime_error("decrypt_failed_cipher_too_small");
  }
  std::vector<unsigned char> out(cipher.size() - crypto_box_SEALBYTES);
  if (crypto_box_seal_open(out.data(), cipher.data(), cipher.size(), pk.data(), sk.data()) != 0) {
    throw std::runtime_error("decrypt_failed");
  }
  return out;
}
