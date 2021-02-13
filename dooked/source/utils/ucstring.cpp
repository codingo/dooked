#include "utils/ucstring.hpp"
#include <cstring> // for memcpy and memset

namespace dooked {
void ucstring_t::resize(size_t const sz) {
  if (sz == len_) {
    return;
  }

  if (sz > capacity_) {
    capacity_ = sz;
    pointer temp = new value_type[sz]{};
    if (len_ > 0) {
      std::memcpy((void *)temp, (void const *)data_, len_);
      delete[] data_;
    }
    data_ = temp;
  } else if (sz < capacity_) {
    auto *new_end = (data_ + sz);
    // zero the rest of the memory but maintain the capacity
    if ((new_end < (data_ + capacity_)) && (*new_end != 0)) {
      std::memset((void *)new_end, 0, (capacity_ - sz));
    }
  }
  len_ = sz;
}

void ucstring_t::clean_up() {
  if (data_) {
    delete[] data_;
  }
  data_ = nullptr;
  capacity_ = len_ = 0;
}

void ucstring_t::clear() { len_ = 0; }

ucstring_t::ucstring_t(const_pointer const data, size_t const len)
    : len_{len}, capacity_{len_}, data_{new unsigned char[len_]{}} {
  memcpy((void *)data_, (void const *)data, len);
}
} // namespace dooked
