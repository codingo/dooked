#include "utils/io_utils.hpp"
#include <iostream>
#include <stdexcept>

bool silent = true;
using namespace dooked;

void require(bool condition, char const *message) {
  if (!condition) throw std::runtime_error(message);
}
template <typename Function> void rejects(Function fn) {
  bool failed = false;
  try { fn(); } catch (std::exception const &) { failed = true; }
  require(failed, "expected invalid input to be rejected");
}
json snapshot(char const *ip, char const *domain = "Example.test") {
  return {{"program", "dooked"}, {"result", json::array({json{{domain,
    {{"dns_probe", json::array({json{{"type", "A"}, {"info", ip}, {"ttl", 60}}})},
     {"content_length", 0}, {"http_code", 200}}}}})}};
}
json record(json const &data, char const *ip) {
  for (auto const &entry : data.at("result"))
    for (auto it = entry.begin(); it != entry.end(); ++it)
      for (auto const &item : it.value().at("dns_probe"))
        if (item.at("info") == ip) return item;
  throw std::runtime_error("record missing");
}
struct test_runtime {
  std::optional<std::vector<json_data_t>> previous_data;
  std::unique_ptr<std::ofstream> output_file;
  std::string output_filename;
  bool first_seen{false};
  std::int64_t last_seen_days{-1};
  std::int64_t last_seen_cutoff{-1};
};

int main() {
  try {
    json empty = {{"result", json::array()}};
    auto first = merge_dns_history(snapshot("192.0.2.1"), empty, 100);
    auto item = record(first, "192.0.2.1");
    require(item["first-seen"] == 100 && item["last-seen"] == 100 && item["seen"] == 1, "first scan");
    require(item["newly-observed"] == true, "new-record event");
    auto same = snapshot("192.0.2.1", "example.TEST");
    same["result"].push_back(same["result"][0]);
    auto second = merge_dns_history(same, first, 200);
    item = record(second, "192.0.2.1");
    require(item["first-seen"] == 100 && item["last-seen"] == 200 && item["seen"] == 2, "duplicate count/case-normalized domain");
    require(item["newly-observed"] == false, "repeat is not first-seen");
    auto rotated = merge_dns_history(snapshot("192.0.2.2"), second, 300);
    auto missing = record(rotated, "192.0.2.1");
    require(missing["seen"] == 2 && missing["last-seen"] == 200 && missing["observed"] == false, "rotation retains old record");
    require(history_missing(missing, 200 + 86400, 1, -1), "inclusive age boundary");
    require(!history_missing(missing, 200 + 86399, 1, -1), "young missing record excluded");
    require(!history_missing(missing, 300, -1, 200), "date boundary is strictly before");
    require(history_missing(missing, 300, -1, 201), "date filter includes earlier record");
    require(!history_missing(record(rotated, "192.0.2.2"), 999999, 0, 999999), "present record excluded");
    auto returned = merge_dns_history(snapshot("192.0.2.1"), rotated, 400);
    require(record(returned, "192.0.2.1")["seen"] == 3, "reappearance count");
    require(record(returned, "192.0.2.1")["first-seen"] == 100, "reappearance preserves origin");
    auto no_answers = merge_dns_history(empty, returned, 500);
    require(no_answers["result"].size() == 1 && record(no_answers, "192.0.2.1")["observed"] == false, "all missing retained");
    auto legacy = merge_dns_history(empty, snapshot("192.0.2.9"), 500);
    auto unknown = record(legacy, "192.0.2.9");
    require(unknown["first-seen"].is_null() && unknown["last-seen"].is_null(), "legacy dates stay unknown");
    require(history_missing(unknown, 500, 0, -1) && !history_missing(unknown, 500, 1, 500), "unknown history is not artificially aged");
    auto migrated = merge_dns_history(snapshot("192.0.2.9"), legacy, 600);
    require(record(migrated, "192.0.2.9")["first-seen"] == 600 && record(migrated, "192.0.2.9")["newly-observed"] == false, "legacy migration is not a new-record event");
    require(history_us_date("01/01/1970") == 0, "epoch date");
    require(history_us_date("03/01/2000") - history_us_date("02/28/2000") == 2 * 86400, "leap century");
    require(history_us_date("03/01/2100") - history_us_date("02/28/2100") == 86400, "non-leap century");
    for (auto const &date : {"02/30/2026", "02/29/2100", "13/01/2026", "01/00/2026", "1/1/2026", "01/01/1969", "01/01/2026x"})
      rejects([&] { history_us_date(date); });
    auto bad = snapshot("192.0.2.9");
    bad["result"][0]["Example.test"]["dns_probe"][0]["seen"] = -1;
    rejects([&] { merge_dns_history(empty, bad, 500); });
    bad["result"][0]["Example.test"]["dns_probe"][0]["seen"] = std::numeric_limits<std::int64_t>::max();
    rejects([&] { merge_dns_history(snapshot("192.0.2.9"), bad, 500); });

    // Real serializer/parser path, including an entirely empty current DNS result.
    auto filename = (std::filesystem::temp_directory_path() / "dooked-history-regression.json").string();
    { std::ofstream output(filename); output << first.dump(); }
    auto previous = get_names<json_data_t>(filename, file_type_e::json_type);
    require(previous && previous->size() == 1, "read existing schema");
    test_runtime args;
    args.previous_data = previous;
    args.output_filename = filename;
    args.output_file = std::make_unique<std::ofstream>(filename);
    map_container_t<probe_result_t> results;
    write_json_result(results, args);
    require(std::filesystem::exists(filename), "empty scan must not delete history output");
    auto roundtrip = get_names<json_data_t>(filename, file_type_e::json_type);
    require(roundtrip && roundtrip->size() == 1 && (*roundtrip)[0].history_record["seen"] == 1, "history survives actual JSON roundtrip");
    std::filesystem::remove(filename);
    std::cout << "PASS: history merge, age/date boundaries, legacy migration, invalid data, and actual JSON roundtrip\n";
    return 0;
  } catch (std::exception const &error) {
    std::cerr << error.what() << "\n";
    return 1;
  }
}
