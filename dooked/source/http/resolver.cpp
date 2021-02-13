#include "http/resolver.hpp"
#include "utils/exceptions.hpp"
#include "utils/string_utils.hpp"

namespace dooked {

http_resolver_t::http_resolver_t(net::io_context &ioc, ssl::context *sslc,
                                 domain_list_t &names,
                                 map_container_t<probe_result_t> &result_map)
    : io_context_(ioc), default_tls_context_(sslc), names_(names),
      result_map_(result_map) {}

void http_resolver_t::send_next_request() {
  try {
    http_retries_count_ = http_redirects_count_ = 0;
    if (!is_default_tls_) {
      default_tls_context_ = tls_holder_->original_ssl_context_;
      is_default_tls_ = 1;
    }
    name_ = names_.next_item();
    perform_http_request();
  } catch (empty_container_exception_t const &) {
  }
}

void http_resolver_t::perform_http_request() {
  http_request_handler_.emplace();
  send_http_request(name_);
}

void http_resolver_t::send_http_request(std::string const &address) {
  auto &http_request =
      http_request_handler_->request_.emplace<http_request_handler_t>(
          io_context_, uri_t{address}.host());
  http_request.start([this](response_type_e const rt, int const content_length,
                            std::string const &response) {
    tcp_request_result(rt, content_length, response);
  });
}

void http_resolver_t::send_https_request(std::string const &address) {
  auto &https_request =
      http_request_handler_->request_.emplace<https_request_handler_t>(
          io_context_, *default_tls_context_, uri_t{address}.host());
  return https_request.start(
      [this](auto const rt, auto const len, auto const &rstr) {
        tcp_request_result(rt, len, rstr);
      });
}

void http_resolver_t::on_resolve_error() {
  auto https_socket_type =
      std::get_if<https_request_handler_t>(&(http_request_handler_->request_));
  if (!https_socket_type) {
    return send_https_request(name_);
  }
  // if we are here, we must have tried https too and it fails.
  result_map_.insert(name_, 0,
                     static_cast<int>(response_type_e::cannot_resolve_name));
  return send_next_request();
}

void http_resolver_t::tcp_request_result(response_type_e const rt,
                                         int const content_length,
                                         std::string const &response_string) {
  switch (rt) {
  case response_type_e::bad_request: {
    result_map_.insert(name_, content_length, 400);
    return send_next_request();
  }
  case response_type_e::forbidden: {
    result_map_.insert(name_, content_length, 403);
    return send_next_request();
  }
  case response_type_e::cannot_resolve_name: {
    return on_resolve_error();
  }
  case response_type_e::cannot_connect:
  case response_type_e::cannot_send: {
    result_map_.insert(name_, 0, static_cast<int>(rt));
    return send_next_request();
  }
  case response_type_e::http_redirected: {
    ++http_redirects_count_;
    if (http_redirects_count_ >= 10) { // too many redirects
      result_map_.insert(name_, 0, 309);
      return send_next_request();
    }
    return send_http_request(response_string);
  }
  case response_type_e::https_redirected: {
    ++http_redirects_count_;
    if (http_redirects_count_ >= 10) { // too many redirects
      result_map_.insert(name_, 0, 309);
      return send_next_request();
    }
    return send_https_request(response_string);
  }
  case response_type_e::not_found: { // HTTP(S) 404
    result_map_.insert(name_, content_length, 404);
    return send_next_request();
  }
  case response_type_e::ok: {
    result_map_.insert(name_, content_length, 200);
    return send_next_request();
  }
  case response_type_e::recv_timed_out: { // retry, wait timeout
    ;
    if (++http_retries_count_ > 3) {
      result_map_.insert(name_, 0, static_cast<int>(rt));
      return send_next_request();
    }
    auto http_socket_type =
        std::get_if<http_request_handler_t>(&(http_request_handler_->request_));
    if (http_socket_type) {
      return send_http_request(response_string);
    } else {
      return send_https_request(response_string);
    }
  }
  case response_type_e::ssl_change_context: {
    return switch_ssl_method(response_string);
  }
  case response_type_e::server_error: {
    result_map_.insert(name_, content_length, 503);
    return send_next_request();
  }
  default: {
    result_map_.insert(name_, 0, 0);
    return send_next_request();
  }
  } // end switch

  send_next_request();
}

void http_resolver_t::switch_ssl_method(std::string const &name) {
  if (!tls_holder_ || is_default_tls_) {
    if (!tls_holder_) { // first time switching SSL context
      auto &tls_v13_context = get_tlsv13_context();
      tls_holder_.emplace(&tls_v13_context, default_tls_context_,
                          ssl_method_e::tls_v13);
    }
    tls_holder_->method_ = ssl_method_e::tls_v13;
    default_tls_context_ = tls_holder_->tls_other_context_;
    is_default_tls_ = 0;
    return send_https_request(name);
  }
  // we must have tried tls v1.2 and tls v1.3, so let's try 1.1
  if (tls_holder_->method_ == ssl_method_e::tls_v13) {
    auto &tls_v11_context = get_tlsv11_context();
    default_tls_context_ = &tls_v11_context;
    is_default_tls_ = 0;
    tls_holder_->method_ = ssl_method_e::tls_v11;
    return send_https_request(name);
  } else if (tls_holder_->method_ == ssl_method_e::tls_v11) {
    auto &tls_v10_context = get_tlsv10_context();
    default_tls_context_ = &tls_v10_context;
    tls_holder_->method_ = ssl_method_e::tls_v10;
    is_default_tls_ = 0;
    return send_https_request(name);
  }

  // if we are here, then the requested TLS is not supported here,
  // so we switch back to tls v1.2 and move on
  default_tls_context_ = tls_holder_->original_ssl_context_;
  is_default_tls_ = 1;
  send_next_request();
}

} // namespace dooked
