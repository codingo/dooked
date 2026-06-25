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

### DNS history metadata

When a previous JSON result is used as input, dooked preserves DNS record
history in each `dns_probe` item:

- `first-seen`: when this DNS record was first observed.
- `last-seen`: when this DNS record was most recently observed.
- `seen`: how many runs have observed this DNS record.
- `currently-seen`: whether this DNS record was present in the latest run.

Historical records that are missing from the latest DNS response are kept in
the JSON output with `currently-seen: false`. This keeps load-balanced or
rotating records searchable without making the default comparison repeatedly
report old historical records as newly missing.

Useful flags:

```
dooked -i previous.json --fs
dooked -i previous.json --ls 2
dooked -i previous.json --lsd "03/15/2021"
```

- `--fs` / `--first-seen`: print records first observed in the current run.
- `--ls` / `--last-seen N`: print missing records last seen at least `N` days ago.
- `--lsd` / `--last-seen-date`: print missing records last seen before a US
  date or datetime, for example `03/15/2021` or `03/15/2021 14:30:00`.
