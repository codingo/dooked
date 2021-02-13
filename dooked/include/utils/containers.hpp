#pragma once

#include "utils/exceptions.hpp"
#include <algorithm>
#include <deque>
#include <map>
#include <mutex>
#include <optional>
#include <queue>
#include <vector>

namespace dooked {

template <typename T> class circular_queue_t {
  std::vector<T> const container_;
  mutable std::mutex mutex_{};
  mutable typename std::vector<T>::size_type index_{};

public:
  circular_queue_t(std::vector<T> &&container)
      : container_{std::move(container)} {}
  T const &next_item() const {
    std::lock_guard<std::mutex> lock_g{mutex_};
    if (index_ >= container_.size()) {
      index_ = 0;
    }
    return container_[index_++];
  }
};

struct http_response_t {
  int content_length_{};
  int http_status_{};
};

template <typename ValueType> struct http_dns_response_t {
  http_response_t http_result_{};
  std::vector<ValueType> dns_result_list_{};
};

// contains result for all searches.
template <typename ValueType> class map_container_t {
  std::map<std::string, http_dns_response_t<ValueType>> map_;
  std::optional<std::mutex> opt_mutex_;

  void append_impl(std::string const &key, ValueType const &value) {
    auto &container = map_[key].dns_result_list_;
    auto iter = std::find(container.cbegin(), container.cend(), value);
    if (iter == container.cend()) {
      container.push_back(value);
    }
  }

  void insert_impl(std::string const &name, int const len,
                   int const http_status) {
    map_[name].http_result_.content_length_ = len;
    map_[name].http_result_.http_status_ = http_status;
  }

public:
  using response_t = http_dns_response_t<ValueType>;
  map_container_t(bool use_lock = false) : map_{}, opt_mutex_{} {
    if (use_lock) {
      opt_mutex_.emplace();
    }
  }
  // needed by different threads
  void append(std::string const &key, ValueType const &value) {
    if (!opt_mutex_) {
      return append_impl(key, value);
    }
    // lock before doing any insertion
    std::lock_guard<std::mutex> lock_g{*opt_mutex_};
    append_impl(key, value);
  }

  void insert(std::string const &name, int const len, int const http_status) {
    if (!opt_mutex_) {
      return insert_impl(name, len, http_status);
    }
    std::lock_guard<std::mutex> lock_g{*opt_mutex_};
    insert_impl(name, len, http_status);
  }
  // only used by main thread, after all "computations" has been
  // done. There's no need for locks here.
  auto &cresult() const { return map_; }
  auto &result() { return map_; }
  bool empty() const { return map_.empty(); }
};

// only one thread does push_backs, which happens way before reading
// however, multiple threads will read from it later.
template <typename T, typename Container = std::deque<T>> class synced_queue_t {
  std::queue<T, Container> container_{};
  std::mutex mutex_{};

public:
  synced_queue_t() = default;
  synced_queue_t(synced_queue_t const &) = delete;
  synced_queue_t(std::queue<T, Container> &&container)
      : container_{std::move(container)} {}
  synced_queue_t(synced_queue_t &&queue)
      : container_{std::move(queue.container_)} {}
  void push_back(T const &item) { container_.push(item); }
  void push_back(T &&item) { container_.push(std::move(item)); }
  T next_item() {
    std::lock_guard<std::mutex> lockg{mutex_};
    if (container_.empty()) {
      throw empty_container_exception_t{};
    }
    T data = container_.front();
    container_.pop();
    return data;
  }
  typename std::queue<T, Container>::size_type size() {
    return container_.size();
  }
  std::queue<T, Container> clone() const { return container_; }
  using value_type = T;
};

using domain_list_t = synced_queue_t<std::string>;
using opt_domain_list_t = std::optional<domain_list_t>;
} // namespace dooked
