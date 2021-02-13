#include "utils/constants.hpp"
#include <cinttypes>

namespace dooked {

std::string code_string(int const http_status_code) {
  if (http_status_code == (int)response_type_e::cannot_connect) {
    return "could not connect";
  } else if (http_status_code == 200) {
    return "200 - OK";
  } else if (http_status_code == (int)response_type_e::cannot_resolve_name) {
    return "could not resolve name";
  } else if (http_status_code == (int)response_type_e::cannot_send) {
    return "unable to send GET request to domain name";
  } else if (http_status_code == 309) {
    return "too many redirection(>10)";
  } else if (http_status_code == (int)response_type_e::not_found ||
             http_status_code == 404) {
    return "404 - Not found";
  } else if (http_status_code == (int)response_type_e::bad_request) {
    return "400 - Bad request";
  } else if (http_status_code == (int)response_type_e::forbidden ||
             http_status_code == 403) {
    return "403 - Forbidden";
  } else if (http_status_code == 503) {
    return "50(0-3) - Server error";
  } else if (http_status_code == (int)response_type_e::recv_timed_out) {
    return "Recv timed out";
  }

  return "unknown error occurred";
}

std::string dns_record_type_to_str(dns_record_type_e type) {
  switch (type) {
  case dns_record_type_e::DNS_REC_A:
    return "A";
  case dns_record_type_e::DNS_REC_AAAA:
    return "AAAA";
  case dns_record_type_e::DNS_REC_AFSDB:
    return "AFSDB";
  case dns_record_type_e::DNS_REC_ANY:
    return "ANY";
  case dns_record_type_e::DNS_REC_APL:
    return "APL";
  case dns_record_type_e::DNS_REC_CAA:
    return "CAA";
  case dns_record_type_e::DNS_REC_CDNSKEY:
    return "CDNSKEY";
  case dns_record_type_e::DNS_REC_CDS:
    return "CDS";
  case dns_record_type_e::DNS_REC_CERT:
    return "CERT";
  case dns_record_type_e::DNS_REC_CNAME:
    return "CNAME";
  case dns_record_type_e::DNS_REC_DHCID:
    return "DHCID";
  case dns_record_type_e::DNS_REC_DLV:
    return "DLV";
  case dns_record_type_e::DNS_REC_DNAME:
    return "DNAME";
  case dns_record_type_e::DNS_REC_DNSKEY:
    return "DNSKEY";
  case dns_record_type_e::DNS_REC_DS:
    return "DS";
  case dns_record_type_e::DNS_REC_HIP:
    return "HIP";
  case dns_record_type_e::DNS_REC_IPSECKEY:
    return "IPSECKEY";
  case dns_record_type_e::DNS_REC_KEY:
    return "KEY";
  case dns_record_type_e::DNS_REC_KX:
    return "KX";
  case dns_record_type_e::DNS_REC_LOC:
    return "LOC";
  case dns_record_type_e::DNS_REC_MX:
    return "MX";
  case dns_record_type_e::DNS_REC_NAPTR:
    return "NAPTR";
  case dns_record_type_e::DNS_REC_NS:
    return "NS";
  case dns_record_type_e::DNS_REC_NSEC:
    return "NSEC";
  case dns_record_type_e::DNS_REC_NSEC3:
    return "NSEC3";
  case dns_record_type_e::DNS_REC_NSEC3PARAM:
    return "NSEC3PARAM";
  case dns_record_type_e::DNS_REC_OPENPGPKEY:
    return "OPENPGPKEY";
  case dns_record_type_e::DNS_REC_PTR:
    return "PTR";
  case dns_record_type_e::DNS_REC_RRSIG:
    return "RRSIG";
  case dns_record_type_e::DNS_REC_RP:
    return "RP";
  case dns_record_type_e::DNS_REC_SIG:
    return "SIG";
  case dns_record_type_e::DNS_REC_SOA:
    return "SOA";
  case dns_record_type_e::DNS_REC_SRV:
    return "SRV";
  case dns_record_type_e::DNS_REC_SSHFP:
    return "SSHFP";
  case dns_record_type_e::DNS_REC_TA:
    return "TA";
  case dns_record_type_e::DNS_REC_TKEY:
    return "TKEY";
  case dns_record_type_e::DNS_REC_TLSA:
    return "TLSA";
  case dns_record_type_e::DNS_REC_TSIG:
    return "TSIG";
  case dns_record_type_e::DNS_REC_TXT:
    return "TXT";
  case dns_record_type_e::DNS_REC_URI:
    return "URI";
  default: {
    std::string numbuf(16, '\0');
    snprintf(numbuf.data(), 16, "%" PRIu16, (uint16_t)type);
    return numbuf;
  }
  }
}

dns_record_type_e dns_str_to_record_type(std::string const &str) {
  // Performance is important here because we may want to use this when reading
  // large numbers of DNS queries from a file.

  switch (tolower(str[0])) {
  case 'a':
    switch (tolower(str[1])) {
    case 0:
      return dns_record_type_e::DNS_REC_A;
    case 'a':
      if (tolower(str[2]) == 'a' && tolower(str[3]) == 'a' && str[4] == 0) {
        return dns_record_type_e::DNS_REC_AAAA;
      }
      return dns_record_type_e::DNS_REC_INVALID;
    case 'f':
      if (tolower(str[2]) == 's' && tolower(str[3]) == 'd' &&
          tolower(str[4]) == 'b' && str[5] == 0) {
        return dns_record_type_e::DNS_REC_AFSDB;
      }
      return dns_record_type_e::DNS_REC_INVALID;
    case 'n':
      if (tolower(str[2]) == 'y' && str[3] == 0) {
        return dns_record_type_e::DNS_REC_ANY;
      }
      return dns_record_type_e::DNS_REC_INVALID;
    case 'p':
      if (tolower(str[2]) == 'l' && str[3] == 0) {
        return dns_record_type_e::DNS_REC_APL;
      }
      return dns_record_type_e::DNS_REC_INVALID;
    default:
      return dns_record_type_e::DNS_REC_INVALID;
    }
  case 'c':
    switch (tolower(str[1])) {
    case 'a':
      if (tolower(str[2]) == 'a' && str[3] == 0) {
        return dns_record_type_e::DNS_REC_CAA;
      }
      return dns_record_type_e::DNS_REC_INVALID;
    case 'd':
      switch (tolower(str[2])) {
      case 's':
        if (str[3] == 0) {
          return dns_record_type_e::DNS_REC_CDS;
        }
        return dns_record_type_e::DNS_REC_INVALID;
      case 'n':
        if (tolower(str[3]) == 's' && tolower(str[4]) == 'k' &&
            tolower(str[5]) == 'e' && tolower(str[6]) == 'y' && str[7] == 0) {
          return dns_record_type_e::DNS_REC_CDNSKEY;
        }
        [[fallthrough]];
      default:
        return dns_record_type_e::DNS_REC_INVALID;
      }
    case 'e':
      if (tolower(str[2]) == 'r' && tolower(str[3]) == 't' && str[4] == 0) {
        return dns_record_type_e::DNS_REC_CERT;
      }
      return dns_record_type_e::DNS_REC_INVALID;
    case 'n':
      if (tolower(str[2]) == 'a' && tolower(str[3]) == 'm' &&
          tolower(str[4]) == 'e' && str[5] == 0) {
        return dns_record_type_e::DNS_REC_CNAME;
      }
      return dns_record_type_e::DNS_REC_INVALID;
    default:
      return dns_record_type_e::DNS_REC_INVALID;
    }
  case 'd':
    switch (tolower(str[1])) {
    case 'h':
      if (tolower(str[2]) == 'c' && tolower(str[3]) == 'i' &&
          tolower(str[4]) == 'd' && str[5] == 0) {
        return dns_record_type_e::DNS_REC_DHCID;
      }
      return dns_record_type_e::DNS_REC_INVALID;
    case 'l':
      if (tolower(str[2]) == 'v' && str[3] == 0) {
        return dns_record_type_e::DNS_REC_DLV;
      }
      return dns_record_type_e::DNS_REC_INVALID;
    case 'n':
      switch (tolower(str[2])) {
      case 'a':
        if (tolower(str[3]) == 'm' && tolower(str[4]) == 'e' && str[5] == 0) {
          return dns_record_type_e::DNS_REC_DNAME;
        }
        return dns_record_type_e::DNS_REC_INVALID;
      case 's':
        if (tolower(str[3]) == 'k' && tolower(str[4]) == 'e' &&
            tolower(str[5]) == 'y' && str[6] == 0) {
          return dns_record_type_e::DNS_REC_DNSKEY;
        }
        return dns_record_type_e::DNS_REC_INVALID;
      default:
        return dns_record_type_e::DNS_REC_INVALID;
      }
    case 's':
      if (str[2] == 0) {
        return dns_record_type_e::DNS_REC_DS;
      }
      return dns_record_type_e::DNS_REC_INVALID;
    default:
      return dns_record_type_e::DNS_REC_INVALID;
    }
  case 'h':
    if (tolower(str[1]) == 'i' && tolower(str[2]) == 'p' && str[3] == 0) {
      return dns_record_type_e::DNS_REC_HIP;
    }
    return dns_record_type_e::DNS_REC_INVALID;
  case 'i':
    if (tolower(str[1]) == 'p' && tolower(str[2]) == 's' &&
        tolower(str[3]) == 'e' && tolower(str[4]) == 'c' &&
        tolower(str[5]) == 'k' && tolower(str[6]) == 'e' &&
        tolower(str[7]) == 'y' && str[8] == 0) {
      return dns_record_type_e::DNS_REC_IPSECKEY;
    }
    return dns_record_type_e::DNS_REC_INVALID;
  case 'k':
    switch (tolower(str[1])) {
    case 'e':
      if (tolower(str[2]) == 'y' && str[3] == 0) {
        return dns_record_type_e::DNS_REC_KEY;
      }
      return dns_record_type_e::DNS_REC_INVALID;
    case 'x':
      if (str[2] == 0) {
        return dns_record_type_e::DNS_REC_KX;
      }
      return dns_record_type_e::DNS_REC_INVALID;
    default:
      return dns_record_type_e::DNS_REC_INVALID;
    }
  case 'l':
    if (tolower(str[1]) == 'o' && tolower(str[2]) == 'c' && str[3] == 0) {
      return dns_record_type_e::DNS_REC_LOC;
    }
    return dns_record_type_e::DNS_REC_INVALID;
  case 'm':
    if (tolower(str[1]) == 'x' && str[2] == 0) {
      return dns_record_type_e::DNS_REC_MX;
    }
    return dns_record_type_e::DNS_REC_INVALID;
  case 'n':
    switch (tolower(str[1])) {
    case 'a':
      if (tolower(str[2]) == 'p' && tolower(str[3]) == 't' &&
          tolower(str[4]) == 'r' && str[5] == 0) {
        return dns_record_type_e::DNS_REC_NAPTR;
      }
      return dns_record_type_e::DNS_REC_INVALID;
    case 's':
      switch (tolower(str[2])) {
      case 0:
        return dns_record_type_e::DNS_REC_NS;
      case 'e':
        if (tolower(str[3]) == 'c') {
          switch (tolower(str[4])) {
          case 0:
            return dns_record_type_e::DNS_REC_NSEC;
          case '3':
            if (str[5] == 0) {
              return dns_record_type_e::DNS_REC_NSEC3;
            }
            if (tolower(str[5]) == 'p' && tolower(str[6]) == 'a' &&
                tolower(str[7]) == 'r' && tolower(str[8]) == 'a' &&
                tolower(str[9]) == 'm' && str[10] == 0) {
              return dns_record_type_e::DNS_REC_NSEC3PARAM;
            }
            return dns_record_type_e::DNS_REC_INVALID;
          default:
            return dns_record_type_e::DNS_REC_INVALID;
          }
        }
        return dns_record_type_e::DNS_REC_INVALID;
      default:
        return dns_record_type_e::DNS_REC_INVALID;
      }
    default:
      return dns_record_type_e::DNS_REC_INVALID;
    }
  case 'o':
    if (tolower(str[1]) == 'p' && tolower(str[2]) == 'e' &&
        tolower(str[3]) == 'n' && tolower(str[4]) == 'p' &&
        tolower(str[5]) == 'g' && tolower(str[6]) == 'p' &&
        tolower(str[7]) == 'k' && tolower(str[8]) == 'e' &&
        tolower(str[9]) == 'y' && str[10] == 0) {
      return dns_record_type_e::DNS_REC_OPENPGPKEY;
    }
    return dns_record_type_e::DNS_REC_INVALID;
  case 'p':
    if (tolower(str[1]) == 't' && tolower(str[2]) == 'r' && str[3] == 0) {
      return dns_record_type_e::DNS_REC_PTR;
    }
    return dns_record_type_e::DNS_REC_INVALID;
  case 'r':
    switch (tolower(str[1])) {
    case 'p':
      if (str[2] == 0) {
        return dns_record_type_e::DNS_REC_RP;
      }
      return dns_record_type_e::DNS_REC_INVALID;
    case 'r':
      if (tolower(str[2]) == 's' && tolower(str[3]) == 'i' &&
          tolower(str[4]) == 'g' && str[5] == 0) {
        return dns_record_type_e::DNS_REC_RRSIG;
      }
      return dns_record_type_e::DNS_REC_INVALID;
    default:
      return dns_record_type_e::DNS_REC_INVALID;
    }
  case 's':
    switch (tolower(str[1])) {
    case 'i':
      if (tolower(str[2]) == 'g' && tolower(str[3]) == 0) {
        return dns_record_type_e::DNS_REC_SIG;
      }
      return dns_record_type_e::DNS_REC_INVALID;
    case 'o':
      if (tolower(str[2]) == 'a' && tolower(str[3]) == 0) {
        return dns_record_type_e::DNS_REC_SOA;
      }
      return dns_record_type_e::DNS_REC_INVALID;
    case 'r':
      if (tolower(str[2]) == 'v' && tolower(str[3]) == 0) {
        return dns_record_type_e::DNS_REC_SRV;
      }
      return dns_record_type_e::DNS_REC_INVALID;
    case 's':
      if (tolower(str[2]) == 'h' && tolower(str[3]) == 'f' &&
          tolower(str[4]) == 'p' && str[5] == 0) {
        return dns_record_type_e::DNS_REC_SSHFP;
      }
      return dns_record_type_e::DNS_REC_INVALID;
    default:
      return dns_record_type_e::DNS_REC_INVALID;
    }
  case 't':
    switch (tolower(str[1])) {
    case 'a':
      if (str[2] == 0) {
        return dns_record_type_e::DNS_REC_TA;
      }
      return dns_record_type_e::DNS_REC_INVALID;
    case 'k':
      if (tolower(str[2]) == 'e' && tolower(str[3]) == 'y' && str[4] == 0) {
        return dns_record_type_e::DNS_REC_TKEY;
      }
      return dns_record_type_e::DNS_REC_INVALID;
    case 'l':
      if (tolower(str[2]) == 's' && tolower(str[3]) == 'a' && str[4] == 0) {
        return dns_record_type_e::DNS_REC_TLSA;
      }
      return dns_record_type_e::DNS_REC_INVALID;
    case 's':
      if (tolower(str[2]) == 'i' && tolower(str[3]) == 'g' && str[4] == 0) {
        return dns_record_type_e::DNS_REC_TSIG;
      }
      return dns_record_type_e::DNS_REC_INVALID;
    case 'x':
      if (tolower(str[2]) == 't' && str[3] == 0) {
        return dns_record_type_e::DNS_REC_TXT;
      }
      return dns_record_type_e::DNS_REC_INVALID;
    default:
      return dns_record_type_e::DNS_REC_INVALID;
    }
  case 'u':
    switch (tolower(str[1])) {
    case 'r':
      if (tolower(str[2]) == 'i' && str[3] == 0) {
        return dns_record_type_e::DNS_REC_URI;
      }
      return dns_record_type_e::DNS_REC_INVALID;
    default:
      return dns_record_type_e::DNS_REC_INVALID;
    }
  case '0':
  case '1':
  case '2':
  case '3':
  case '4':
  case '5':
  case '6':
  case '7':
  case '8':
  case '9':
    return (dns_record_type_e)std::stoi(str);
  default:
    return dns_record_type_e::DNS_REC_INVALID;
  }
}

} // namespace dooked
