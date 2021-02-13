#include "dns/dns.hpp"
#include <vector>

#ifdef _WIN32
#include <Ws2tcpip.h>
#include <winsock2.h>
#else
#include <arpa/inet.h> // for in_addr and in6_addr
#include <string.h>    // for memcpy, memset etc
#endif                 // _WIN32

namespace dooked {

bool parse_name(std::uint8_t const *begin, std::uint8_t const *buf,
                std::uint8_t const *end, unsigned char *name, std::uint8_t *len,
                std::uint8_t **next) {
  std::uint8_t first{};
  int label_type{};
  int label_len{};
  int name_len{};
  std::uint8_t *pointer{nullptr};

  while (true) {
    if (buf >= end) {
      return false;
    }
    first = *buf;
    label_type = (first & 0xC0);
    if (label_type == 0xC0) // Compressed
    {
      if (next && !pointer) {
        *next = (std::uint8_t *)buf + 2;
      }
      pointer = (std::uint8_t *)(begin + (htons(*((uint16_t *)buf)) & 0x3FFF));
      if (pointer >= buf) {
        return false;
      }
      buf = pointer;
    } else if (label_type == 0x00) // Uncompressed
    {
      label_len = (first & 0x3F);
      name_len += label_len + 1;
      if (name_len >= 0xFF) {
        return false;
      }
      if (label_len == 0) {
        if (name_len == 1) {
          *(name++) = '.';
        }
        *name = 0;
        if (next && !pointer) {
          *next = (std::uint8_t *)(buf + label_len + 1);
        }
        if (name_len <= 1) {
          *len = (std::uint8_t)name_len;
        } else {
          *len = (std::uint8_t)(name_len - 1);
        }
        return true;
      } else {
        if (buf + label_len + 1 > end) {
          return false;
        }
        memcpy(name, buf + 1, (size_t)label_len);
        *(name + label_len) = '.';
        name += label_len + 1;
        buf += label_len + 1;
      }
    } else {
      return false;
    }
  }
}

bool dns_parse_record_raw(std::uint8_t *begin, std::uint8_t *buf,
                          std::uint8_t const *end, std::uint8_t **next,
                          dns_alternate_record_t &record) {
  if (!parse_name(begin, buf, end, record.name.name, &record.name.name_length,
                  next)) {
    return false;
  }
  if (*next + 10 > end) {
    return false;
  }

  record.type = (dns_record_type_e)ntohs((*(uint16_t *)(*next)));
  record.dns_class_ = ntohs((*(uint16_t *)(*next + 2)));
  record.ttl = ntohl((*(uint32_t *)(*next + 4)));
  record.rd_length = ntohs((*(uint16_t *)(*next + 8)));
  *next = *next + 10;
  record.data.raw = *next;

  *next = *next + record.rd_length;
  if (*next > end) {
    return false;
  }
  return true;
}

bool dns_parse_record(std::uint8_t *begin, std::uint8_t *buf,
                      std::uint8_t const *end, std::uint8_t **next,
                      dns_alternate_record_t &record) {
  if (!dns_parse_record_raw(begin, buf, end, next, record)) {
    return false;
  }

  if (record.type == dns_record_type_e::DNS_REC_A) {
    if (record.rd_length != 4) {
      return false;
    }
  } else if (record.type == dns_record_type_e::DNS_REC_AAAA) {
    if (record.rd_length != 16) {
      return false;
    }
  } else if (record.type == dns_record_type_e::DNS_REC_NS) {
    if (record.rd_length > 0xFF) {
      return false;
    }
    static_string_t name{};
    if (!parse_name(begin, record.data.raw, end, record.data.name.name,
                    &record.data.name.name_length, nullptr)) {
      return false;
    }
  }

  return true;
}

bool dns_print_readable(char **buf, std::size_t buflen,
                        unsigned char const *source, std::size_t len) {
  char *endbuf = *buf + buflen;
  for (size_t i = 0; i < len; i++) {
    if (source[i] >= ' ' && source[i] <= '~' && source[i] != '\\') {
      if (*buf >= endbuf - 1) {
        **buf = 0;
        return false;
      }
      *((*buf)++) = source[i];
    } else {
      if (*buf >= endbuf - 4) {
        **buf = 0;
        return false;
      }
      *((*buf)++) = '\\';
      *((*buf)++) = 'x';
      char hex1 = (char)((source[i] >> 8) & 0xF);
      char hex2 = (char)(source[i] & 0xF);
      *((*buf)++) = (char)(hex1 + (hex1 < 10 ? '0' : ('a' - 10)));
      *((*buf)++) = (char)(hex2 + (hex2 < 10 ? '0' : ('a' - 10)));
    }
  }
  **buf = 0;
  return true;
}

std::string dns_raw_record_data_to_str(dns_alternate_record_t &record,
                                       std::uint8_t *begin, std::uint8_t *end) {
  static constexpr int const raw_buf_size = 0xFFFF;
  std::string raw_buf(raw_buf_size, '\0');
  auto buf = raw_buf.data();
  static_string_t name;

  char *ptr = buf;

  switch (record.type) {
  case dns_record_type_e::DNS_REC_NS:
  case dns_record_type_e::DNS_REC_CNAME:
  case dns_record_type_e::DNS_REC_DNAME:
  case dns_record_type_e::DNS_REC_PTR:
    parse_name(begin, record.data.raw, end, name.name, &name.name_length,
               nullptr);
    dns_print_readable(&ptr, raw_buf_size, name.name, name.name_length);
    break;
  case dns_record_type_e::DNS_REC_MX: {
    if (record.rd_length < 3) {
      goto raw;
    }
    parse_name(begin, record.data.raw + 2, end, name.name, &name.name_length,
               nullptr);
    int no =
        sprintf(buf, "%" PRIu16 " ", ntohs(*((uint16_t *)record.data.raw)));
    ptr += no;
    dns_print_readable(&ptr, raw_buf_size, name.name, name.name_length);
  } break;
  case dns_record_type_e::DNS_REC_TXT: {
    auto record_end = record.data.raw + record.rd_length;
    auto data_ptr = record.data.raw;
    while (data_ptr < record_end) {
      auto length = *(data_ptr++);
      if (data_ptr + length <= record_end) {
        *(ptr++) = '"';
        dns_print_readable(&ptr, raw_buf_size, data_ptr, length);
        data_ptr += length;
        *(ptr++) = '"';
        *(ptr++) = ' ';
      } else {
        break;
      }
    }
    *ptr = 0;
    break;
  }
  case dns_record_type_e::DNS_REC_SOA: {
    std::uint8_t *next;
    // We have 5 32-bit values plus two names.
    if (record.rd_length < 22) {
      goto raw;
    }

    parse_name(begin, record.data.raw, end, name.name, &name.name_length,
               &next);
    dns_print_readable(&ptr, raw_buf_size, name.name, name.name_length);
    *(ptr++) = ' ';

    if (next + 20 >= record.data.raw + record.rd_length) {
      goto raw;
    }
    parse_name(begin, next, end, name.name, &name.name_length, &next);
    dns_print_readable(&ptr, raw_buf_size, name.name, name.name_length);
    *(ptr++) = ' ';
    if (next + 20 > record.data.raw + record.rd_length) {
      goto raw;
    }

    sprintf(ptr, "%" PRIu32 " %" PRIu32 " %" PRIu32 " %" PRIu32 " %" PRIu32,
            ntohl(*((uint32_t *)next)), ntohl(*(((uint32_t *)next) + 1)),
            ntohl(*(((uint32_t *)next) + 2)), ntohl(*(((uint32_t *)next) + 3)),
            ntohl(*(((uint32_t *)next) + 4)));
    break;
  }
  case dns_record_type_e::DNS_REC_A: {
    if (record.rd_length != 4) {
      goto raw;
    }
    inet_ntop(AF_INET, record.data.raw, buf, raw_buf_size);
  } break;
  case dns_record_type_e::DNS_REC_AAAA: {
    if (record.rd_length != 16) {
      goto raw;
    }
    inet_ntop(AF_INET6, record.data.raw, buf, raw_buf_size);
  } break;
  case dns_record_type_e::DNS_REC_CAA: {
    if (record.rd_length < 2 || record.data.raw[1] < 1 ||
        record.data.raw[1] > 15 || record.data.raw[1] + 2 > record.rd_length) {
      goto raw;
    }
    int written =
        sprintf(ptr, "%" PRIu8 " ", (std::uint8_t)(record.data.raw[0] >> 7));
    if (written < 0) {
      raw_buf.clear();
      return raw_buf;
    }
    ptr += written;
    dns_print_readable(&ptr, raw_buf_size, record.data.raw + 2,
                       record.data.raw[1]);
    *(ptr++) = ' ';
    *(ptr++) = '"';
    dns_print_readable(&ptr, raw_buf_size,
                       record.data.raw + 2 + record.data.raw[1],
                       (size_t)(record.rd_length - record.data.raw[1] - 2));
    *(ptr++) = '"';
    *ptr = 0;
  } break;
  raw:
  default:
    dns_print_readable(&ptr, raw_buf_size, record.data.raw, record.rd_length);
    *ptr = 0;
  }
  auto const len_ = strlen(raw_buf.c_str());
  raw_buf.resize(len_);
  return raw_buf;
}

void dns_extract_query_result(int const answer_count, dns_packet_t &packet,
                              std::uint8_t *begin, std::size_t len,
                              std::uint8_t *next) {
  for (int i = 0; i < answer_count; ++i) {
    dns_alternate_record_t rec{};
    if (dns_parse_record_raw(begin, next, begin + len, &next, rec)) {
      probe_result_t result{};
      result.type = rec.type;
      result.ttl = rec.ttl;
      result.rdata = dns_raw_record_data_to_str(rec, begin, begin + len);
      packet.body.answers.push_back(std::move(result));
    }
  }
}

} // namespace dooked
