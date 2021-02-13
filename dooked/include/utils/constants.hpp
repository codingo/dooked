#pragma once

#include <cstdint>
#include <string>

namespace dooked {

enum class file_type_e { txt_type, json_type, unknown_type };

enum class response_type_e : std::uint8_t {
  ok = 0,
  cannot_resolve_name = 1,
  unknown_response = 2,
  server_error = 5,
  recv_timed_out = 6,
  cannot_connect = 11,
  cannot_send = 12,
  http_redirected = 31,
  https_redirected = 32,
  not_found = 44,
  bad_request = 40,
  forbidden = 43,
  ssl_change_context = 70,
  ssl_timed_out = 71
};

enum class dns_record_type_e : std::uint16_t {
  DNS_REC_UNDEFINED = 0,
  DNS_REC_A = 1,
  DNS_REC_NS = 2,
  DNS_REC_CNAME = 5,
  DNS_REC_SOA = 6,
  DNS_REC_PTR = 12,
  DNS_REC_MX = 15,
  DNS_REC_TXT = 16,
  DNS_REC_RP = 17,
  DNS_REC_AFSDB = 18,
  DNS_REC_SIG = 24,
  DNS_REC_KEY = 25,
  DNS_REC_AAAA = 28,
  DNS_REC_LOC = 29,
  DNS_REC_SRV = 33,
  DNS_REC_NAPTR = 35,
  DNS_REC_KX = 36,
  DNS_REC_CERT = 37,
  DNS_REC_DNAME = 39,
  DNS_REC_APL = 42,
  DNS_REC_DS = 43,
  DNS_REC_SSHFP = 44,
  DNS_REC_IPSECKEY = 45,
  DNS_REC_RRSIG = 46,
  DNS_REC_NSEC = 47,
  DNS_REC_DNSKEY = 48,
  DNS_REC_DHCID = 49,
  DNS_REC_NSEC3 = 50,
  DNS_REC_NSEC3PARAM = 51,
  DNS_REC_TLSA = 52,
  DNS_REC_HIP = 55,
  DNS_REC_CDS = 59,
  DNS_REC_CDNSKEY = 60,
  DNS_REC_OPENPGPKEY = 61,
  DNS_REC_TKEY = 249,
  DNS_REC_TSIG = 250,
  DNS_REC_ANY = 255,
  DNS_REC_URI = 256,
  DNS_REC_CAA = 257,
  DNS_REC_TA = 32768,
  DNS_REC_DLV = 32769,
  DNS_REC_INVALID = 0xFFFF, // Error code
};

// http://www.tcpipguide.com/free/t_DNSMessageHeaderandQuestionSectionFormat.htm

enum class dns_rcode_e {
  DNS_RCODE_NO_ERROR = 0,
  DNS_RCODE_FORMAT_ERR = 1,
  DNS_RCODE_SERVER_FAILED = 2,
  DNS_RCODE_NXDOMAIN = 3, // non-existing domain
  DNS_RCODE_NOT_IMPLEMENTED = 4,
  DNS_RCODE_REFUSED = 5,
  DNS_RCODE_YXDOMAIN = 6, // name exists when it should not
  DNS_RCODE_YXRRSET = 7,  // resource record set exist when it should not
  DNS_RCODE_NXRRSET = 8,  // rr set that should exist does not
  DNS_RCODE_NOTAUTH = 9,
  DNS_RCODE_NOTZONE = 10,
  DNS_RCODE_BADVERS = 16,
  DNS_RCODE_BADKEY = 17,
  DNS_RCODE_BADTIME = 18,
  DNS_RCODE_BADMODE = 19,
  DNS_RCODE_BADNAME = 20,
  DNS_RCODE_BADALG = 21,
  DNS_RCODE_BADTRUNC = 22,
  DNS_RCODE_BADCOOKIE = 23
};

std::string code_string(int const http_status_code);
std::string dns_record_type_to_str(dns_record_type_e);
dns_record_type_e dns_str_to_record_type(std::string const &str);
} // namespace dooked
