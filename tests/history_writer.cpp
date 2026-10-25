#include "utils/io_utils.hpp"
#include <cassert>
#include <cstdio>
struct args_t {
  std::string output_filename;
  std::unique_ptr<std::ofstream> output_file;
  std::optional<std::vector<dooked::json_data_t>> previous_data;
  bool first_seen = false;
  int last_seen_days = -1;
  std::string last_seen_date;
  bool history_silent = true;
};
int main(int argc, char **argv) {
  using namespace dooked;
  assert(argc == 2);
  args_t args;
  args.output_filename = argv[1];
  args.output_file = std::make_unique<std::ofstream>(args.output_filename);
  map_container_t<probe_result_t> records;
  records.append("example.test", {"192.0.2.1", dns_record_type_e::DNS_REC_A, 60});
  write_json_result(records, args);
  std::ifstream file(args.output_filename);
  json output; file >> output;
  auto record = output["result"][0]["example.test"]["dns_probe"][0];
  assert(record.contains("first-seen"));
  assert(record.contains("last-seen"));
  assert(record["seen"] == 1);
  auto previous = get_names<json_data_t>(args.output_filename, file_type_e::json_type);
  assert(previous && previous->size() == 1);
  args.previous_data = previous;
  args.output_file = std::make_unique<std::ofstream>(args.output_filename);
  map_container_t<probe_result_t> rotated;
  rotated.append("example.test", {"192.0.2.2", dns_record_type_e::DNS_REC_A, 60});
  write_json_result(rotated, args);
  auto retained = get_names<json_data_t>(args.output_filename, file_type_e::json_type);
  assert(retained && retained->size() == 2);
  args.previous_data = retained;
  args.output_file = std::make_unique<std::ofstream>(args.output_filename);
  write_json_result(records, args);
  auto reappeared = get_names<json_data_t>(args.output_filename, file_type_e::json_type);
  assert(reappeared && reappeared->size() == 2);
  bool found = false;
  for (auto const &item : *reappeared) {
    if (item.rdata == "192.0.2.1") {
      found = true;
      assert(item.metadata["seen"] == 2);
      assert(item.metadata["first-seen"] == record["first-seen"]);
    }
  }
  assert(found);
  // An empty scan must preserve the history file and its old observations.
  args.previous_data = reappeared;
  args.output_file = std::make_unique<std::ofstream>(args.output_filename);
  map_container_t<probe_result_t> empty;
  std::ostringstream messages;
  auto *saved = std::cout.rdbuf(messages.rdbuf());
  for (auto &item : *args.previous_data)
    item.metadata["last-seen"] = "2020-01-01T00:00:00Z";
  args.last_seen_days = 2;
  args.history_silent = false;
  write_json_result(empty, args);
  std::cout.rdbuf(saved);
  assert(messages.str().find("[LAST-SEEN]") != std::string::npos);
  assert(get_names<json_data_t>(args.output_filename, file_type_e::json_type)->size() == 2);
  // Date cutoff excludes records seen on/after the date; silent hides reports.
  args.last_seen_days = -1;
  args.last_seen_date = "01/01/2019";
  args.output_file = std::make_unique<std::ofstream>(args.output_filename);
  messages.str(""); saved = std::cout.rdbuf(messages.rdbuf());
  write_json_result(empty, args);
  std::cout.rdbuf(saved);
  assert(messages.str().empty());
  args.last_seen_date = "01/01/2021";
  args.history_silent = true;
  args.output_file = std::make_unique<std::ofstream>(args.output_filename);
  saved = std::cout.rdbuf(messages.rdbuf());
  write_json_result(empty, args);
  std::cout.rdbuf(saved);
  assert(messages.str().empty());
  args.history_silent = false;
  args.output_file = std::make_unique<std::ofstream>(args.output_filename);
  saved = std::cout.rdbuf(messages.rdbuf());
  write_json_result(empty, args);
  std::cout.rdbuf(saved);
  assert(messages.str().find("[LAST-SEEN]") != std::string::npos);
  args.previous_data.reset();
  args.first_seen = true;
  args.last_seen_date.clear();
  args.output_file = std::make_unique<std::ofstream>(args.output_filename);
  messages.str(""); saved = std::cout.rdbuf(messages.rdbuf());
  write_json_result(records, args);
  std::cout.rdbuf(saved);
  assert(messages.str().find("[FIRST-SEEN]") != std::string::npos);
  puts("PASS: writer metadata, JSON roundtrip, rotation, reappearance, empty scan, first/day/date alerts, silent");
}
