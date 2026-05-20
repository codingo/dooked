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

### DNS history tracking

JSON output now records DNS history on each `dns_probe` entry:

- `first_seen`: first date the record was observed (`YYYY-MM-DD`)
- `last_seen`: latest date the record was observed (`YYYY-MM-DD`)
- `seen`: number of runs where the record was observed

When a previous JSON result is used as input, dooked preserves old records that are
not seen in the current run. This makes load-balanced targets easier to track,
because a rotating IP is not lost just because it disappeared from one scan.

Useful flags:

```bash
# Print records discovered for the first time in this run
dooked --fs -i domains.txt -o current.json

# Re-scan a previous result and report records not seen in the last 30 days
dooked --ls 30 -i current.json -o next.json

# Report records last seen before a specific US date
dooked --lsd 01/31/2026 -i current.json -o next.json
```
