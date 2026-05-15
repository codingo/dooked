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

Use `--checks` or `--check-config` to load custom notification checks from a
JSON file. A config may be a JSON array or an object with a `checks` array:

```json
{
  "checks": [
    {
      "field": "domain",
      "regex": "(dev|test)",
      "alert": "domain contains an environment marker",
      "ignore_case": true
    },
    {
      "field": "body",
      "regex": "Copyright 2020",
      "alert": "outdated copyright banner"
    }
  ]
}
```

Supported fields are `domain`, DNS fields (`type`, `info`/`rdata`, `ttl`),
HTTP fields (`http_code`, `code_string`, `content_length`), and response body
aliases (`body`, `response_body`, `page_content`, `content`). Response bodies
are kept only in memory for matching, capped at 64 KiB per request, and are not
written to the JSON output file.
