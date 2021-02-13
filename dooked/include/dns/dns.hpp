#pragma once

#ifdef _MSC_VER
#include <ws2tcpip.h>
#pragma warning(disable : 4996)
#endif

#include "utils/probe_result.hpp"
#include "utils/ucstring.hpp"

#include <inttypes.h>
#include <string>
#include <vector>

namespace dooked {

struct static_string_t {
  unsigned char name[0xFF]{};
  std::uint8_t name_length{};
};

struct dns_question_t {
  static_string_t dns_name{};
  dns_record_type_e type{};
  unsigned int dns_class_{};
};

struct dns_header_t {
  bool rd{};
  bool tc{};
  bool aa{};
  bool qr{};
  bool ad{};
  bool z{};
  bool cd{};
  bool ra{};

  std::uint8_t rcode{};
  std::uint8_t opcode{};
  std::uint16_t id{};
};

struct dns_head_t {
  dns_header_t header{};
  std::vector<dns_question_t> questions{};
};

struct dns_alternate_record_t {
  static_string_t name{};
  dns_record_type_e type{};   // RR TYPE (2 octets)
  std::uint16_t dns_class_{}; // RR CLASS codes(2 octets)
  std::uint16_t rd_length{};  // length in octets of the RDATA field.
  std::uint32_t ttl{};        // time to live(4 octets)
  union rd_data_u {
    std::uint8_t *raw;
    static_string_t name;
    rd_data_u() : raw{nullptr} {}
  } data; // RData
};

struct dns_body_t {
  std::vector<probe_result_t> answers{};
};

struct dns_packet_t {
  dns_head_t head{};
  dns_body_t body{};
};

bool parse_name(std::uint8_t const *begin, std::uint8_t const *buf,
                std::uint8_t const *end, unsigned char *name, std::uint8_t *len,
                std::uint8_t **next);

void trim_string(std::string &);
dns_record_type_e dns_str_to_record_type(std::string const &str);
bool dns_parse_record_raw(std::uint8_t *begin, std::uint8_t *buf,
                          std::uint8_t const *end, std::uint8_t **next,
                          dns_alternate_record_t &record);
bool dns_parse_record(std::uint8_t *begin, std::uint8_t *buf,
                      std::uint8_t const *end, std::uint8_t **next,
                      dns_alternate_record_t &record);
bool dns_print_readable(char **buf, size_t buflen, unsigned char const *source,
                        size_t len);
bool case_insensitive_compare(std::string const &a, std::string const &b);
std::string dns_raw_record_data_to_str(dns_alternate_record_t &record,
                                       std::uint8_t *begin, std::uint8_t *end);
void dns_extract_query_result(int, dns_packet_t &packet, std::uint8_t *begin,
                              std::size_t len, std::uint8_t *next);
} // namespace dooked
