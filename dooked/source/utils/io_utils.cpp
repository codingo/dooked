#include "utils/io_utils.hpp"

namespace dooked {

void to_json(json &j, probe_result_t const &record) {
  j = json{{"ttl", record.ttl},
           {"type", dns_record_type_to_str(record.type)},
           {"info", record.rdata}};
  if constexpr (has_tracking_fields_v<probe_result_t>) {
    j["first-seen"] = record.first_seen;
    j["last-seen"] = record.last_seen;
    j["seen"] = record.seen_count;
  }
}

void from_json(json const &j, probe_result_t &record) {
  record.ttl = j.value("ttl", std::uint32_t{0});
  record.type = dns_str_to_record_type(j.value("type", std::string{}));
  record.rdata = j.value("info", std::string{});
  if constexpr (has_tracking_fields_v<probe_result_t>) {
    record.first_seen = j.value("first-seen", std::uint64_t{0});
    record.last_seen = j.value("last-seen", std::uint64_t{0});
    record.seen_count = j.value("seen", std::uint32_t{0});
  }
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

} // namespace dooked
