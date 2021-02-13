#pragma once

#include <stddef.h> // for size_t

namespace dooked {

/*
we need a unsigned char string type(ucstring_t) that doesn't
automatically append a '\0' after the sequence. It also try
to avoid as many (re-)allocations as much as it can.
*/

class ucstring_t {
  size_t len_{};
  size_t capacity_{};
  unsigned char *data_ = nullptr;

private:
  void clean_up();

public:
  using value_type = unsigned char;
  using pointer = value_type *;
  using const_pointer = value_type const *;

public:
  ucstring_t() {}
  ucstring_t(const_pointer, size_t);
  ~ucstring_t() { clean_up(); }
  pointer data() { return data_; }
  const_pointer cdata() const { return const_cast<const_pointer>(data_); }
  void resize(size_t sz);
  size_t size() const { return len_; }
  void clear();
  value_type &operator[](size_t index) { return data_[index]; }
};

class ucstring_view_t {
  size_t const len_;
  unsigned char const *data_;

public:
  using value_type = unsigned char const;
  using pointer = value_type *;
  using const_pointer = pointer;

public:
  ucstring_view_t(const_pointer d, size_t sz) : len_{sz}, data_{d} {}
  ucstring_view_t(ucstring_t const &s) : len_{s.size()}, data_{s.cdata()} {}
  ucstring_view_t(ucstring_t const &s, size_t sz)
      : len_{sz}, data_{s.cdata()} {}
  size_t size() const { return len_; }
  size_t length() const { return len_; }
  pointer data() const { return data_; }
  const_pointer cdata() const { return data_; }
};
} // namespace dooked
