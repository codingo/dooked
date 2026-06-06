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

When a previous JSON scan is passed back as input, dooked now carries DNS
record history forward:

- `first-seen`: first scan time for a domain/type/value tuple
- `last-seen`: most recent scan time where that tuple was observed
- `seen`: number of scans where that tuple was observed
- `currently_seen`: whether the tuple appeared in the latest scan

This keeps rotating DNS records in the output after they disappear from the
latest scan, so load-balanced targets can be reviewed without losing older
addresses immediately.

Additional comparison flags:

- `--fs`: report records first seen in the current scan
- `--ls N`: report records missing from the current scan that have not been
  seen in at least `N` days
- `--lsd MM/DD/YYYY`: report missing records last seen before a US-formatted
  date. `MM/DD/YYYY HH:MM:SS` is also accepted.
