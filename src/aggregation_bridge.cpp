#include <cstdlib>
#include <stdexcept>
#include <string>

void run_aggregation_bridge(const std::string& input_dir, const std::string& weights_path, const std::string& output_path) {
  std::string cmd = "python3 -m tas_helper.aggregate --inputs '" + input_dir + "' --weights '" + weights_path + "' --output '" + output_path + "'";
  int rc = std::system(cmd.c_str());
  if (rc != 0) {
    throw std::runtime_error("aggregation helper failed");
  }
}
