#include "http/requests_handler.hpp"
#include "utils/random_utils.hpp"
#include <boost/beast/http/read.hpp>
#include <boost/beast/http/write.hpp>
#include <mutex>

// defined in dooked.cpp
extern bool no_bytes_count;
extern bool silent;

namespace dooked {

http_request_handler_t::http_request_handler_t(net::io_context &io_context,
                                               std::string domain_name)
    : io_{io_context}, domain_{std::move(domain_name)} {}

void http_request_handler_t::start(completion_cb_t cb) {
  callback_ = std::move(cb);
  prepare_request();
  establish_connection();
}

void http_request_handler_t::prepare_request() {
  request_.emplace();
  request_->method(http::verb::get);
  request_->version(11);
  request_->target("/");
  request_->keep_alive(true);
  request_->set(http::field::host, domain_);
  request_->set(http::field::cache_control, "no-cache");
  request_->set(http::field::user_agent, get_random_agent());
  request_->set(http::field::accept, "*/*");
}

void http_request_handler_t::establish_connection() {
  if (resolved_ip_addresses_.empty()) {
    return resolve_name();
  }
  socket_.emplace(io_);
  socket_->expires_after(std::chrono::seconds(DOOKED_MAX_HTTP_WAIT_TIME));
  socket_->async_connect(
      resolved_ip_addresses_.cbegin(), resolved_ip_addresses_.cend(),
      [=](auto const &ec, auto const &) { on_connected(ec); });
}

void http_request_handler_t::resolve_name() {
  if (resolver_) {
    if (callback_) {
      callback_(response_type_e::cannot_resolve_name, 0, "");
    }
    return;
  }
  resolver_.emplace(io_);
  resolver_->async_resolve(
      domain_, "http", [this](auto const &error, auto const &results) {
        if (error) {
          if (callback_) {
            callback_(response_type_e::cannot_resolve_name, 0, error.message());
          }
          return;
        }
        resolved_ip_addresses_.clear();
        resolved_ip_addresses_.reserve(results.size());
        for (auto const &r : results) {
          resolved_ip_addresses_.push_back(r.endpoint());
        }
        return establish_connection();
      });
}

void http_request_handler_t::on_connected(beast::error_code const ec) {
  if (ec) {
    return reconnect();
  }
  send_http_data();
}

void http_request_handler_t::reconnect() {
  if (++connect_retries_ >= 3) {
    if (callback_) {
      callback_(response_type_e::cannot_connect, 0, {});
    }
    return;
  }
  establish_connection();
}

void http_request_handler_t::send_http_data() {
  socket_->expires_after(std::chrono::seconds(DOOKED_MAX_HTTP_WAIT_TIME));
  http::async_write(*socket_, *request_,
                    [this](auto const ec, std::size_t const sz) {
                      if (ec) {
                        return resend_data();
                      }
                      receive_data();
                    });
}

void http_request_handler_t::resend_data() {
  if (++send_retries_ >= 3) {
    if (callback_) {
      return callback_(response_type_e::cannot_send, 0, {});
    }
  } else {
    send_http_data();
  }
}

void http_request_handler_t::receive_data() {
  socket_->expires_after(std::chrono::seconds(DOOKED_MAX_HTTP_WAIT_TIME));
  response_.emplace();
  buffer_ = {};

  http::async_read(*socket_, buffer_, *response_,
                   [this](auto const ec, std::size_t const sz) {
                     on_data_received(ec, sz);
                   });
}

void http_request_handler_t::on_data_received(
    beast::error_code const ec, std::size_t const bytes_received) {

  response_type_e response_int = response_type_e::unknown_response;
  if (ec) {
#ifdef _DEBUG
    if (!silent) {
      report_error("HTTP error: {}", ec.message());
    }
#endif // _DEBUG
    if (callback_) {
      callback_(response_type_e::recv_timed_out, 0, {});
    }
    return;
  }
  auto const http_status_code = response_->result_int();
  int const status_code_simple = http_status_code / 100;
  std::string response_string{};

  if (status_code_simple == 2) {
    response_int = response_type_e::ok;
  } else if (status_code_simple == 3) { // redirected
    response_string = (*response_)[http::field::location].to_string();
    if (response_string.empty()) {
      response_int = response_type_e::unknown_response;
    } else {
      if (starts_with(response_string, "https://")) {
        response_int = response_type_e::https_redirected;
      } else {
        response_int = response_type_e::http_redirected;
      }
    }
  } else if (status_code_simple == 4) {
    if (http_status_code == 404) {
      response_int = response_type_e::not_found;
    } else if (http_status_code == 400) {
      response_int = response_type_e::bad_request;
    } else if (http_status_code == 403) {
      response_int = response_type_e::forbidden;
    }
  } else if (status_code_simple == 5) {
    response_int = response_type_e::server_error;
  } else {
#ifdef _DEBUG
    if (!silent) {
      report_error("HTTP else: {}", response_->body());
    }
#endif // _DEBUG
    response_int = response_type_e::unknown_response;
  }

  int content_length{};
  if (response_->has_content_length()) {
    try {
      auto const cl_str = (*response_)[http::field::content_length].to_string();
      content_length = std::stoi(cl_str);
    } catch (std::exception const &) {
    }
  } else {
    if (auto const body_size = response_->payload_size();
        body_size.has_value()) {
      content_length = (int)(*body_size);
    } else if (!no_bytes_count) {
      content_length = bytes_received;
    }
  }
  if (callback_) {
    callback_(response_int, content_length, response_string);
  }
}

// ================== HTTPS ================================

https_request_handler_t::https_request_handler_t(net::io_context &io_context,
                                                 net::ssl::context &ssl_context,
                                                 std::string name)
    : io_{io_context}, ssl_context_{ssl_context},
      domain_name_(std::move(name)) {}

void https_request_handler_t::start(completion_cb_t callback) {
  callback_ = std::move(callback);
  prepare_request_data();
  connect();
}

void https_request_handler_t::perform_ssl_ritual() {
  if (!SSL_set_tlsext_host_name(ssl_stream_->native_handle(),
                                domain_name_.c_str())) {
    beast::error_code ec{static_cast<int>(::ERR_get_error()),
                         net::error::get_ssl_category()};
  }
}

void https_request_handler_t::perform_ssl_handshake() {
  beast::get_lowest_layer(*ssl_stream_)
      .expires_after(std::chrono::seconds(DOOKED_MAX_HTTP_WAIT_TIME));
  ssl_stream_->async_handshake(
      net::ssl::stream_base::client,
      [=](boost::system::error_code ec) { return on_ssl_handshake(ec); });
}

void https_request_handler_t::on_ssl_handshake(
    boost::system::error_code const ec) {
  if (ec) {
    bool const ssl_error = ec.category() == net::error::get_ssl_category();
#ifdef _DEBUG
    auto const err_message = ec.message();
    if (!silent) {
      report_error("SSL handshake({})({}): {}\n", ec.value(), ssl_error,
                   err_message);
    }
#endif // _DEBUG
    response_type_e error_type{response_type_e::unknown_response};
    if (!ssl_error) { // most likely a timeout
      error_type = response_type_e::ssl_timed_out;
    } else {
      error_type = response_type_e::ssl_change_context;
    }
    if (callback_) {
      callback_(error_type, 0, domain_name_);
    }
    return;
  }
  send_https_data();
}

void https_request_handler_t::send_https_data() {
  beast::get_lowest_layer(*ssl_stream_)
      .expires_after(std::chrono::seconds(DOOKED_MAX_HTTP_WAIT_TIME));
  http::async_write(
      *ssl_stream_, *get_request_,
      beast::bind_front_handler(&https_request_handler_t::on_data_sent, this));
}

void https_request_handler_t::on_data_sent(beast::error_code ec, std::size_t) {
  if (ec) {
    if (callback_) {
      callback_(response_type_e::cannot_send, 0, ec.message());
    }
    return;
  }
  receive_data();
}

void https_request_handler_t::prepare_request_data() {
  get_request_.emplace();
  get_request_->method(http::verb::get);
  get_request_->version(11);
  get_request_->target("/");
  get_request_->keep_alive(true);
  get_request_->set(http::field::host, domain_name_);
  get_request_->set(http::field::cache_control, "no-cache");
  get_request_->set(http::field::user_agent, get_random_agent());
  get_request_->set(http::field::accept, "*/*");
}

void https_request_handler_t::receive_data() {
  response_.emplace();
  recv_buffer_.emplace();
  beast::get_lowest_layer(*ssl_stream_)
      .expires_after(std::chrono::seconds(DOOKED_MAX_HTTP_WAIT_TIME));
  http::async_read(*ssl_stream_, *recv_buffer_, *response_,
                   [this](beast::error_code ec, std::size_t const sz) {
                     on_data_received(ec, sz);
                   });
}

void https_request_handler_t::connect() {
  if (resolved_ip_addresses_.empty()) {
    return resolve_name();
  }
  ssl_stream_.emplace(io_, ssl_context_);
  perform_ssl_ritual();

  beast::get_lowest_layer(*ssl_stream_)
      .expires_after(std::chrono::seconds(DOOKED_MAX_HTTP_WAIT_TIME));
  beast::get_lowest_layer(*ssl_stream_)
      .async_connect(resolved_ip_addresses_.cbegin(),
                     resolved_ip_addresses_.cend(),
                     [=](auto const &ec, auto const &) { on_connect(ec); });
}

void https_request_handler_t::reconnect() {
  if (++reconnect_count_ >= 3) {
    if (callback_) {
      callback_(response_type_e::cannot_connect, 0, {});
    }
    return;
  }
  connect();
}

void https_request_handler_t::on_connect(beast::error_code const ec) {
  if (ec) {
#ifdef _DEBUG
    if (!silent) {
      report_error("Could not connect. Will reconnect now...");
    }
#endif
    return reconnect();
  }
  perform_ssl_handshake();
}

void https_request_handler_t::resolve_name() {
  if (resolver_) { // we have tried resolving the name earlier
    if (callback_) {
      callback_(response_type_e::cannot_resolve_name, 0, "");
    }
    return;
  }
  resolver_.emplace(io_);
  resolver_->async_resolve(
      domain_name_, "https", [this](auto const &error, auto const &results) {
        if (error) {
          if (callback_) {
            callback_(response_type_e::cannot_resolve_name, 0, error.message());
            return;
          }
        }
        resolved_ip_addresses_.clear();
        resolved_ip_addresses_.reserve(results.size());
        for (auto const &r : results) {
          resolved_ip_addresses_.push_back(r.endpoint());
        }
        return connect();
      });
}

void https_request_handler_t::on_data_received(
    beast::error_code const ec, std::size_t const bytes_received) {
  response_type_e response_int = response_type_e::unknown_response;
  if (ec) {
    if (ec == beast::error::timeout) {
      response_int = response_type_e::recv_timed_out;
    }
    if (callback_) {
      callback_(response_int, 0, domain_name_);
    }
    return;
  }
  int const status_code = response_->result_int();
  int const status_code_simple = status_code / 100;
  std::string response_string{};

  if (status_code_simple == 2) {
    response_int = response_type_e::ok;
  } else if (status_code_simple == 3) { // redirected
    response_string = (*response_)[http::field::location].to_string();
    if (response_string.empty()) {
      response_int = response_type_e::unknown_response;
    } else {
      if (starts_with(response_string, "https://")) {
        response_int = response_type_e::https_redirected;
      } else {
        response_int = response_type_e::http_redirected;
      }
    }
  } else if (status_code_simple == 4) {
    if (status_code == 404) {
      response_int = response_type_e::not_found;
    } else if (status_code == 400) {
      response_int = response_type_e::bad_request;
    } else if (status_code == 403) {
      response_int = response_type_e::forbidden;
    }
  } else if (status_code_simple == 5) {
    response_int = response_type_e::server_error;
  } else {
    response_int = response_type_e::unknown_response;
  }

  int content_length = 0;
  if (response_->has_content_length()) {
    try {
      auto const cl_str = (*response_)[http::field::content_length].to_string();
      content_length = std::stoi(cl_str);
    } catch (std::exception const &) {
    }
  } else {
    if (auto const body_size = response_->payload_size();
        body_size.has_value()) {
      content_length = (int)(*body_size);
    } else if (!no_bytes_count) {
      content_length = bytes_received;
    }
  }
  if (callback_) {
    callback_(response_int, content_length, response_string);
  }
}

void setup_tls_context_client(std::unique_ptr<ssl::context> &ssl_context,
                              ssl_method_e const method) {
  static std::mutex ssl_global_mutex{};
  if (!ssl_context) {
    std::lock_guard<std::mutex> lock_g{ssl_global_mutex};
    // by the time this thread acquires the mutex, context may have been
    // initialized, so check again
    if (ssl_context) {
      return;
    }
    auto const client_type = static_cast<net::ssl::context::method>(method);
    ssl_context = std::make_unique<net::ssl::context>(client_type);
    ssl_context->set_default_verify_paths();
    ssl_context->set_verify_mode(net::ssl::verify_none);
    ssl_context->set_options(net::ssl::context::default_workarounds |
                             net::ssl::context::no_sslv2 |
                             net::ssl::context::no_sslv3);
  }
}

net::ssl::context &get_tlsv13_context() {
  // tls 1.3
  static std::unique_ptr<net::ssl::context> ssl_context{nullptr};
  setup_tls_context_client(ssl_context, ssl_method_e::tls_v13);
  return *ssl_context;
}

net::ssl::context &get_tlsv11_context() {
  // tls 1.1
  static std::unique_ptr<net::ssl::context> ssl_context{nullptr};
  setup_tls_context_client(ssl_context, ssl_method_e::tls_v11);
  return *ssl_context;
}

net::ssl::context &get_tlsv10_context() {
  // tls 1.0
  static std::unique_ptr<net::ssl::context> ssl_context{nullptr};
  setup_tls_context_client(ssl_context, ssl_method_e::tls_v10);
  return *ssl_context;
}

} // namespace dooked
