#include <sodium.h>
#include <cstdlib>
#include <iostream>

void run_http_server();

int main() {
  try {
    if (sodium_init() < 0) {
      throw std::runtime_error("sodium_init_failed");
    }
    run_http_server();
    return 0;
  } catch (const std::exception& ex) {
    std::cerr << "tas_server failed: " << ex.what() << std::endl;
    return 1;
  }
}
