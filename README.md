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

Use `--checks <file>` or `--check-config <file>` to load custom alert checks
from a JSON configuration file while dooked is running:

```
dooked -i domains.txt -o results --checks checks.json
```

The config may be either a JSON array or an object with a `checks` array. Each
check requires `field`, `regex`, and `alert`. `pattern` is accepted as an alias
for `regex`, `message` is accepted as an alias for `alert`, and checks are
case-sensitive unless `ignore_case: true` or `case_sensitive: false` is set.

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
      "field": "content",
      "regex": "Copyright 2020",
      "alert": "outdated copyright banner"
    },
    {
      "field": "rdata",
      "regex": "v=spf1",
      "alert": "SPF TXT record found"
    }
  ]
}
```

Supported fields are domain aliases (`domain`, `domain_name`), DNS record fields
(`type`, `info`, `rdata`, `ttl`), HTTP fields (`content_length`, `http_code`,
`http_status`, `code_string`), and response body aliases (`body`,
`response_body`, `page_content`, `content`). Response bodies are kept only in
memory for matching, capped at the first 64 KiB, and are not written to the JSON
result file.
