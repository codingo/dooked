#include "utils/history.hpp"
#include <cassert>
#include <iostream>
using dooked::history::json;
json record(char const *ip, char const *type = "A") {
  return json{{"type",type},{"info",ip},{"ttl",60}};
}
json::array_t scan(std::initializer_list<json> records) {
  return {json{{"example.test",json{{"dns_probe",records}, {"http_code",200}, {"content_length",10}}}}};
}
int main() {
  using namespace dooked::history;
  auto first = scan({record("192.0.2.1")});
  auto events = merge(first, {}, "2026-01-01T00:00:00Z");
  assert(events.size()==1 && events[0].fresh);
  auto rotating = scan({record("192.0.2.2")});
  events = merge(rotating, first, "2026-01-02T00:00:00Z");
  assert(events.size()==2);
  assert(rotating[0]["example.test"]["dns_probe"].size()==2);
  auto third = scan({record("192.0.2.1")});
  events = merge(third, rotating, "2026-01-04T00:00:00Z");
  auto seen = third[0]["example.test"]["dns_probe"][0];
  assert(seen["first-seen"]=="2026-01-01T00:00:00Z");
  assert(seen["last-seen"]=="2026-01-04T00:00:00Z");
  assert(seen["seen"]==2);
  assert(events.size()==1 && !events[0].fresh);
  json::array_t empty;
  merge(empty, third, "2026-01-05T00:00:00Z");
  assert(empty[0]["example.test"]["dns_probe"].size()==2);
  auto legacy = scan({record("192.0.2.9")});
  auto current = scan({record("192.0.2.9")});
  events = merge(current, legacy, "2026-01-06T00:00:00Z");
  assert(events.empty());
  assert(current[0]["example.test"]["dns_probe"][0]["seen"]==1);
  auto cname = scan({record("Target.TEST", "CNAME")});
  merge(cname, {}, "2026-01-01T00:00:00Z");
  auto cname2 = scan({record("target.test", "CNAME")});
  assert(merge(cname2, cname, "2026-01-02T00:00:00Z").empty());
  assert(cname2[0]["example.test"]["dns_probe"][0]["seen"]==2);
  assert(cutoff_date("02/29/2024")=="2024-02-29T00:00:00Z");
  for (auto bad : {"02/29/2025","13/01/2026","01/01/2026junk",""}) {
    bool rejected=false;
    try { cutoff_date(bad); } catch(std::invalid_argument const &) { rejected=true; }
    assert(rejected);
  }
  std::cout << "PASS: rotation, reappearance, absent domains, legacy, case matching, date validation\n";
}
