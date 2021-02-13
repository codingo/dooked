#pragma once

#include "dns.hpp"
#include "http/requests_handler.hpp"
#include "utils/containers.hpp"
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/steady_timer.hpp>
#include <optional>

// max dns wait time in seconds
#define DOOKED_MAX_DNS_WAIT_TIME 10
#define DOOKED_MAX_RETRIES 3
#define DOOKED_MAX_REDIRECTS 5

namespace dooked {
namespace net = boost::asio;

struct resolver_address_t {
  net::ip::udp::endpoint ep{};
};

using dns_rec_list_t = std::array<dns_record_type_e, 7>;
struct dns_supported_record_type_t {
  static dns_rec_list_t const supported_types;
};

using udp_stream_t = net::ip::udp::socket;
using error_code_t = boost::system::error_code;
using resolver_list_t = circular_queue_t<resolver_address_t>;

class custom_resolver_socket_t {
  net::io_context &io_;
  domain_list_t &names_;
  resolver_list_t &resolvers_;
  map_container_t<probe_result_t> &result_map_;
  net::ssl::context *ssl_context_{nullptr};
  std::optional<udp_stream_t> udp_stream_{};
  std::optional<net::ip::udp::endpoint> default_ep_{};
  std::optional<net::steady_timer> timer_{};
  std::optional<request_t> http_request_handler_{};
  std::optional<temporary_ssl_holder_t> other_tls_holder_{};
  resolver_address_t current_resolver_{};
  int last_processed_dns_index_{-1};
  int http_retries_count_{};
  int http_redirects_count_{};
  int dns_retries_ = 0;
  int const supported_dns_record_size_;
  dns_record_type_e current_rec_type_{};
  static constexpr std::size_t const sizeof_packet_header{12};
  ucstring_t send_buffer_{};
  ucstring_t recv_buffer_{};
  std::string name_{};
  bool deferring_http_request_{false};
  bool is_default_tls_{true};

  // dns related member functions
private:
  dns_record_type_e dns_next_record_type();
  void dns_send_network_request();
  void dns_receive_network_data();
  void dns_establish_udp_connection();
  void dns_on_data_sent();
  void dns_on_data_received(error_code_t, std::size_t);
  void dns_send_next_request();
  void dns_serialize_packet(dns_packet_t const &);
  void dns_continue_probe();

  // http related "handlers"
  void perform_http_request();
  void http_result_obtained(response_type_e, int, std::string const &);
  void on_http_resolve_error();
  void send_https_request(std::string const &address);
  void send_http_request(std::string const &address);
  void http_switch_tls_requested(std::string const &);
  bool parse_dns_response(dns_packet_t &, ucstring_t &);

public:
  custom_resolver_socket_t(net::io_context &, net::ssl::context *,
                           domain_list_t &, resolver_list_t &,
                           map_container_t<probe_result_t> &);
  void defer_http_request(bool const defer);
  void start();
};

void dns_create_query(std::string const &name, std::uint16_t const type,
                      std::uint16_t const id, ucstring_t &bufp);
std::string rcode_to_string(dns_rcode_e);
std::uint16_t get_random_integer();
} // namespace dooked
