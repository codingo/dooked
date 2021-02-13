#pragma once

#include <boost/asio/io_context.hpp>
#include <boost/asio/ssl/context.hpp>
#include <boost/asio/ssl/stream.hpp>
#include <boost/beast/core/error.hpp>
#include <boost/beast/core/flat_buffer.hpp>
#include <boost/beast/core/tcp_stream.hpp>
#include <boost/beast/http/empty_body.hpp>
#include <boost/beast/http/message.hpp>
#include <boost/beast/http/string_body.hpp>

#include "utils/constants.hpp"

#include <optional>
#include <variant>

// max http wait time in seconds
#define DOOKED_MAX_HTTP_WAIT_TIME 30

namespace dooked {
namespace net = boost::asio;
namespace ssl = net::ssl;
namespace beast = boost::beast;
namespace http = beast::http;

enum class ssl_method_e {
  tls_v10 = net::ssl::context::tlsv1_client,
  tls_v11 = net::ssl::context::tlsv11_client,
  tls_v12 = net::ssl::context::tlsv12_client,
  tls_v13 = net::ssl::context::tlsv13_client,
  undefined
};

using completion_cb_t = std::function<void(response_type_e, int, std::string)>;

class http_request_handler_t {
  net::io_context &io_;
  std::string domain_{};
  std::vector<net::ip::tcp::endpoint> resolved_ip_addresses_{};
  std::optional<beast::tcp_stream> socket_{};
  std::optional<net::ip::tcp::resolver> resolver_{};
  std::optional<http::response<http::string_body>> response_{};
  std::optional<http::request<http::empty_body>> request_{};
  beast::flat_buffer buffer_{};
  int connect_retries_{};
  int send_retries_{};
  // int receive_retries_{};
  completion_cb_t callback_{nullptr};

private:
  void establish_connection();
  void resolve_name();
  void on_connected(beast::error_code);
  void prepare_request();
  void send_http_data();
  void receive_data();
  void reconnect();
  void resend_data();
  void on_data_received(beast::error_code, std::size_t);

public:
  http_request_handler_t(net::io_context &, std::string);
  void start(completion_cb_t = nullptr);
};

class https_request_handler_t {
  net::io_context &io_;
  net::ssl::context &ssl_context_;
  std::string domain_name_{};
  std::optional<ssl::stream<beast::tcp_stream>> ssl_stream_{};
  std::optional<http::request<http::empty_body>> get_request_{};
  std::optional<http::response<http::string_body>> response_{};
  std::optional<net::ip::tcp::resolver> resolver_{};
  std::optional<beast::flat_buffer> recv_buffer_{};
  std::vector<net::ip::tcp::endpoint> resolved_ip_addresses_{};
  completion_cb_t callback_{nullptr};
  int reconnect_count_{};

private:
  void perform_ssl_ritual();
  void connect();
  void receive_data();
  void reconnect();
  void send_https_data();
  void on_data_sent(beast::error_code, std::size_t const);
  void prepare_request_data();
  void on_connect(beast::error_code);
  void on_data_received(beast::error_code, std::size_t const);
  void perform_ssl_handshake();
  void on_ssl_handshake(boost::system::error_code);
  void resolve_name();

public:
  https_request_handler_t(net::io_context &, net::ssl::context &, std::string);
  void start(completion_cb_t = nullptr);
};

// needed to
struct dummy_struct_t {};

struct request_t {
  std::variant<dummy_struct_t, http_request_handler_t, https_request_handler_t>
      request_;
};

struct temporary_ssl_holder_t {
  ssl::context *tls_other_context_; // tls v10, v11 or v13
  ssl::context *original_ssl_context_;
  ssl_method_e method_;
  temporary_ssl_holder_t(ssl::context *cr, ssl::context *cp, ssl_method_e m)
      : tls_other_context_{cr}, original_ssl_context_{cp}, method_{m} {}
};

void setup_tls_context_client(std::unique_ptr<ssl::context> &, ssl_method_e);
net::ssl::context &get_tlsv10_context();
net::ssl::context &get_tlsv11_context();
net::ssl::context &get_tlsv13_context();
bool starts_with(std::string const &str, std::string const &prefix);
void report_error(std::string const &);
void report_error(char const *, std::string const &);
void report_error(char const *format, int, bool, std::string const &);

} // namespace dooked
