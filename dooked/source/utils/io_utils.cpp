#include "utils/io_utils.hpp"

namespace dooked {

void to_json(json &j, probe_result_t const &record) {
  j = json{{"ttl", record.ttl},
           {"type", dns_record_type_to_str(record.type)},
           {"info", record.rdata}};
}

bool is_text_file(std::string const &file_extension) {
  return file_extension.find(".txt") != std::string::npos ||
         file_extension.find("text/plain") != std::string::npos;
}

bool is_json_file(std::string const &file_extension) {
  return file_extension.find(".json") != std::string::npos ||
         file_extension.find("application/json") != std::string::npos;
}

std::string get_file_type(std::filesystem::path const &file_path) {
  if (file_path.has_extension()) {
    return file_path.extension().string();
  }

  std::string result{};
#ifdef _WIN32
  // haven't figured what to do on Windows
#else
  std::string const command = "file -ib " + file_path.string();
  auto file = popen(command.c_str(), "r");
  if (!file) {
    return {};
  }
  char buffer[128]{};
  while (!feof(file)) {
    if (fgets(buffer, sizeof(buffer), file) == nullptr) {
      break;
    }
    result += buffer;
  }
  pclose(file);
#endif
  return result;
}

std::string get_filepath(std::string const &filename) {
  if (filename.empty()) {
    return {};
  }
  return std::filesystem::path(filename).replace_extension().string();
}

std::string current_us_datetime() {
  auto const current_time = std::time(nullptr);
#if _MSC_VER && !__INTEL_COMPILER
#pragma warning(disable : 4996)
#endif
  auto const local_time = std::localtime(&current_time);
  if (!local_time) {
    return {};
  }

  std::string output;
  output.resize(32);
  auto const trimmed_size =
      std::strftime(output.data(), output.size(), "%m/%d/%Y %H:%M:%S",
                    local_time);
  if (trimmed_size == 0) {
    return {};
  }
  output.resize(trimmed_size);
  return output;
}

} // namespace dooked
