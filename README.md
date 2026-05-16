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

### History tracking

When a previous JSON output file is passed back as input, dooked now carries
record history forward into the next JSON output:

- `first-seen`: when this DNS record first appeared in dooked output
- `last-seen`: when this DNS record was last observed
- `seen`: how many runs have observed the same domain/type/value tuple

The history metadata makes load-balanced records less noisy because an IP can
rotate out of a single run without losing when it was first and last observed.
Records from previous JSON input are preserved in the next output when they are
not observed in the current run, with their previous `last_seen` value intact.

Additional reporting flags:

```sh
dooked -i previous.json --fs
dooked -i previous.json --ls 2
dooked -i previous.json --lsd 05/16/2026
```

- `--fs` reports DNS records that are first seen in the current run.
- `--ls <days>` reports records from the previous JSON that are missing from
  the current run and were last seen at least `<days>` days ago.
- `--lsd <MM/DD/YYYY>` reports missing records last seen on or before the
  supplied US-formatted date.

### Runtime regex checks

Use `--checks <file.json>` to load custom regex alerts at runtime. The config
can be either an array or an object with a `checks` array:

```json
{
  "checks": [
    {
      "field": "domain",
      "regex": "(dev|test)",
      "alert": "development-looking domain",
      "ignore_case": true
    },
    {
      "field": "page_content",
      "regex": "Copyright 2024",
      "alert": "outdated copyright banner"
    },
    {
      "field": "content_length",
      "regex": "^[1-9][0-9]{5,}$",
      "alert": "large response body"
    }
  ]
}
```

Supported fields are `domain`, `domain_name`, `type`, `rdata`, `info`, `ttl`,
`http_code`, `code_string`, `content_length`, `body`, `page_content`,
`response_body`, `first-seen`, `first_seen`, `last-seen`, `last_seen`, and
`seen`. Use `"field": "*"` to run a regex against every supported field.
Response bodies are capped in memory for runtime checks and are not written
into JSON output.
