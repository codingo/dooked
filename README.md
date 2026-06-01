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

When a previous JSON result is used as input, dooked now keeps DNS records that
were seen in earlier runs and annotates each record with:

- `first-seen`: UTC time the record first appeared in the dataset
- `last-seen`: UTC time the record was most recently observed
- `seen`: number of runs where the record was observed

This helps with load-balanced targets where valid records rotate between runs.
The following flags surface the history:

```sh
dooked -i previous.json --fs
dooked -i previous.json --ls 2
dooked -i previous.json --lsd 05/31/2026
```

- `--fs` reports records first seen during the current run.
- `--ls <days>` reports records missing from the current run and not seen for
  at least that many days.
- `--lsd <MM/DD/YYYY>` reports records missing from the current run and last
  seen on or before that date.
