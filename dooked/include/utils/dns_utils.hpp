#pragma once

namespace dooked {
template <typename Value>
constexpr void set_16bit_value(unsigned char *p, Value const value) {
  p[0] = static_cast<unsigned char>((value >> 8) & 0xFF);
  p[1] = static_cast<unsigned char>(value & 0xFF);
}

template <typename Value>
constexpr void set_qid(unsigned char *p, Value const value) {
  set_16bit_value(p, value);
}

template <typename T, typename V>
constexpr void set_opcode(T &target, V const &value) {
  target[2] |= static_cast<unsigned char>((value & 0xF) << 3);
}

template <typename T, typename V>
constexpr void set_opcode_rd(T &target, V const &value) {
  target[2] |= static_cast<unsigned char>(value & 0x1);
}

template <typename V>
constexpr void set_qd_count(unsigned char *t, V const &v) {
  set_16bit_value(t + 4, v);
}

template <typename V>
constexpr void set_question_type(unsigned char *t, V const &v) {
  set_16bit_value(t, v);
}

template <typename V>
constexpr void set_question_class(unsigned char *t, V const &v) {
  set_16bit_value(t + 2, v);
}

} // namespace dooked
