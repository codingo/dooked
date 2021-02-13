#pragma once

#include <array>
#include <string>

namespace dooked {

char get_random_char();
std::string get_random_string(std::uint16_t const length);
std::uint16_t get_random_integer();
std::string get_random_agent();

using user_agent_list_t = std::array<std::string, 14>;
struct request_agent_t {
  static user_agent_list_t const user_agents;
};

} // namespace dooked
