# dooked
DNS and Target HTTP History Local Storage and Search

[![License](https://img.shields.io/badge/license-GPL3-_red.svg)](https://www.gnu.org/licenses/gpl-3.0.en.html) [![Twitter](https://img.shields.io/badge/twitter-@codingo__-blue.svg)](https://twitter.com/codingo_)

## Installation
- Download Boost Library from the [official website](https://www.boost.org/users/download/)
- Extract the library into any directory
- Set the environment variable BOOST_ROOT to the location of Boost

For example:

```
wget "https://dl.bintray.com/boostorg/release/1.75.0/source/boost_1_75_0.tar.gz" -o "/usr/home/boost_1_75_0.tar.gz"
tar -xzvf /usr/home/boost_1_75_0.tar.gz
export BOOST_ROOT="/usr/home/boost_1_75_0/"
printenv | grep BOOST_ROOT
```

Alternatively, you can add the `boost` library via various `apt` respositorys.

Then clone `dooked` and compile it, as follows:

```
git clone "https://github.com/codingo/dooked.git"
cd dooked
git submodule update --init
cd dooked/CLI11 && git checkout tags/v1.9.1
cd ../
cmake .
make
```

## Requirements
- Boost C++ library
- cmake
- any C++ compiler (supporting C++17) or MSVC(for Windows).

## Usage

For comprehensive help, use `dooked --help`

### Runtime regex checks

Use `--checks <file>` to load custom alerts from a JSON config and match them
against collected domain, DNS, HTTP, or page content fields.

```json
{
  "checks": [
    {
      "field": "domain",
      "regex": "(dev|test)",
      "alert": "domain name contains an environment marker",
      "ignore_case": true
    },
    {
      "field": "response_body",
      "regex": "copyright 2025",
      "alert": "page may contain an outdated copyright banner",
      "ignore_case": true
    }
  ]
}
```

Supported fields:

- `domain` / `domain_name`
- `type` / `record_type`
- `info` / `rdata`
- `ttl`
- `content_length`
- `http_code`
- `http_status` / `code_string`
- `response_body` / `body` / `page_content` / `content`

Example:

```sh
dooked -i domains.txt --checks checks.json
```
