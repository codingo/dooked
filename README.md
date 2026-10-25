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

### DNS record history

JSON output stores `first-seen` and `last-seen` as UTC timestamps
(`YYYY-MM-DDTHH:MM:SSZ`) and `seen` as the number of scans observing a record.
Feed the previous JSON output back with `-i` to continue its history. Records
are identified by domain, DNS type and value (case insensitive), so rotating
addresses retain independent histories. Missing records remain in the output;
they do not advance `last-seen` or `seen`.

- `--fs`: report records observed for the first time in this scan.
- `--ls N`: report records absent this scan whose last observation was more
  than N days ago (`--ls 0` reports any dated absent records).
- `--lsd MM/DD/YYYY`: report absent records last observed before that date,
  at midnight UTC. This option and `--ls` are mutually exclusive.

These flags replace immediate DNS change/missing alerts with history reports;
HTTP comparisons still run. `--silent` suppresses history reports. History is
saved even without the flags. For example:

```sh
dooked -i previous.json -o next --fs --ls 2
```

Legacy JSON files are accepted. A legacy record's first known timestamp and
count start when it is next observed; an absent legacy record is preserved
without an invented date and cannot trigger a date-based alert yet.

Local regression tests (no network requests):

```sh
c++ -std=c++17 -Idooked/include -Idooked/json/single_include \
  tests/history.cpp -o /tmp/dooked-history-test
/tmp/dooked-history-test
c++ -std=c++17 -Idooked/include -Idooked/json/single_include \
  tests/history_writer.cpp dooked/source/utils/io_utils.cpp \
  dooked/source/utils/constants.cpp dooked/source/utils/string_utils.cpp \
  -o /tmp/dooked-writer-test
/tmp/dooked-writer-test /tmp/dooked-history-output.json
```
