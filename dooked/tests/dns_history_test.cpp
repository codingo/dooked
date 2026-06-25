#include "utils/io_utils.hpp"

#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace {

void check(bool condition, char const *message) {
  if (!condition) {
    throw std::runtime_error(message);
  }
}

struct test_runtime_args_t {
  std::optional<std::vector<dooked::json_data_t>> previous_data{};
  std::unique_ptr<std::ofstream> output_file{};
  std::string output_filename{};
};

dooked::json::array_t dns_probe_for(dooked::json const &output,
                                    std::string const &domain) {
  auto const &results = output.at("result").get_ref<dooked::json::array_t const &>();
  for (auto const &entry : results) {
    auto const object = entry.get<dooked::json::object_t>();
    auto const found = object.find(domain);
    if (found != object.end()) {
      return found->second.at("dns_probe").get<dooked::json::array_t>();
    }
  }
  throw std::runtime_error("domain not found: " + domain);
}

dooked::json::object_t record_for(dooked::json::array_t const &records,
                                  std::string const &rdata) {
  for (auto const &record : records) {
    auto const object = record.get<dooked::json::object_t>();
    if (object.at("info").get<std::string>() == rdata) {
      return object;
    }
  }
  throw std::runtime_error("record not found: " + rdata);
}

} // namespace

int main() try {
  std::string const previous_json = R"json(
{
  "program": "dooked",
  "result": [
    {
      "Example.COM": {
        "content_length": 123,
        "http_code": 200,
        "dns_probe": [
          {
            "ttl": 60,
            "type": "A",
            "info": "1.1.1.1",
            "first_seen": "01/02/2024 00:00:00",
            "last_seen": "01/03/2024 00:00:00",
            "seen": 3,
            "currently_seen": true
          },
          {
            "ttl": 60,
            "type": "A",
            "info": "2.2.2.2",
            "first-seen": "01/02/2024 00:00:00",
            "last-seen": "01/03/2024 00:00:00",
            "seen": 2,
            "currently-seen": true
          }
        ]
      }
    },
    {
      "old.example": {
        "content_length": 77,
        "http_code": 200,
        "dns_probe": [
          {
            "ttl": 300,
            "type": "A",
            "info": "3.3.3.3",
            "first-seen": "01/01/2024 00:00:00",
            "last-seen": "01/02/2024 00:00:00",
            "seen": 1,
            "currently-seen": true
          }
        ]
      }
    }
  ]
}
)json";

  auto previous_data =
      dooked::detail::read_json_string<dooked::json_data_t>(
          previous_json.cbegin(), previous_json.cend());
  check(previous_data.has_value(), "previous data should parse");
  check(previous_data->size() == 3, "previous data should include 3 records");
  check((*previous_data)[0].first_seen == "01/02/2024 00:00:00",
        "snake_case first_seen should be read");
  check((*previous_data)[0].last_seen == "01/03/2024 00:00:00",
        "snake_case last_seen should be read");
  check((*previous_data)[0].currently_seen,
        "snake_case currently_seen should be read");

  dooked::map_container_t<dooked::probe_result_t> result_map{};
  result_map.insert("example.com", 456, 200);
  result_map.append("example.com",
                    {"1.1.1.1", dooked::dns_record_type_e::DNS_REC_A, 120});

  auto const output_path =
      std::filesystem::temp_directory_path() / "dooked_dns_history_test.json";
  test_runtime_args_t rt_args{};
  rt_args.previous_data = std::move(previous_data);
  rt_args.output_filename = output_path.string();
  rt_args.output_file = std::make_unique<std::ofstream>(output_path);

  dooked::write_json_result(result_map, rt_args);

  std::ifstream output_file{output_path};
  dooked::json output = dooked::json::parse(output_file);
  auto const &example_records = dns_probe_for(output, "example.com");
  check(example_records.size() == 2,
        "example.com should include current and historical records");

  auto const &current_record = record_for(example_records, "1.1.1.1");
  check(current_record.at("first-seen") == "01/02/2024 00:00:00",
        "current record should preserve first-seen");
  check(current_record.at("seen") == 4,
        "current record should increment seen count");
  check(current_record.at("currently-seen") == true,
        "current record should be marked currently-seen");

  auto const &historical_record = record_for(example_records, "2.2.2.2");
  check(historical_record.at("first-seen") == "01/02/2024 00:00:00",
        "historical record should preserve first-seen");
  check(historical_record.at("last-seen") == "01/03/2024 00:00:00",
        "historical record should preserve last-seen");
  check(historical_record.at("seen") == 2,
        "historical record should preserve seen count");
  check(historical_record.at("currently-seen") == false,
        "historical record should be marked not currently-seen");

  auto const &old_records = dns_probe_for(output, "old.example");
  check(old_records.size() == 1,
        "missing domain should be preserved in output history");
  auto const &old_record = record_for(old_records, "3.3.3.3");
  check(old_record.at("currently-seen") == false,
        "missing domain record should be marked not currently-seen");
  check(old_record.at("last-seen") == "01/02/2024 00:00:00",
        "missing domain record should preserve last-seen");

  output_file.close();
  std::filesystem::remove(output_path);
  std::cout << "dns history metadata test passed\n";
  return 0;
} catch (std::exception const &error) {
  std::cerr << "dns history metadata test failed: " << error.what() << "\n";
  return 1;
}
