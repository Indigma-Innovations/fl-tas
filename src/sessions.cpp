#include <filesystem>
#include <fstream>
#include <nlohmann/json.hpp>

void write_json(const std::string& path, const nlohmann::json& payload) {
  std::ofstream out(path);
  out << payload.dump(2);
}

nlohmann::json read_json(const std::string& path) {
  std::ifstream in(path);
  nlohmann::json payload;
  in >> payload;
  return payload;
}

void create_session_layout(const std::string& root, const std::string& session_id, const nlohmann::json& meta) {
  auto base = root + "/sessions/" + session_id;
  std::filesystem::create_directories(base + "/inputs");
  std::filesystem::create_directories(base + "/aggregate");
  write_json(base + "/meta.json", meta);
}
