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

### DNS history

Feed a previous JSON output into the next run to retain history:

```sh
dooked -i domains.txt -o first --fs
dooked -i first.json -o second --fs --ls 2
dooked -i second.json -o third --lsd 10/01/2026
```

Each DNS record (case-normalized domain, record type, exact record data) carries
`first-seen` and `last-seen` as UTC Unix seconds, and `seen` as the number of
scans that observed it. Duplicate answers count once per scan. Missing records
remain in the output with `observed: false`, so an IP that rotates out and later
returns keeps its original history. `scan-time` records the completed scan time.

- `--fs` reports records not present in the previous history. A reappearing
  historical record does not produce a new-record notification.
- `--ls N` reports records absent from the current scan whose last observation
  is at least N complete 24-hour days old. `--ls 0` reports all absent records.
- `--lsd MM/DD/YYYY` reports absent records last observed strictly before that
  date's UTC midnight. Dates are validated, including leap years; negative day
  thresholds are rejected. If both missing-record options are supplied, either
  matching condition causes one report.
- `--silent` suppresses these added history notifications; history is still
  written. Existing comparison behavior remains available.

Older snapshots without history fields remain readable. Their unknown dates
stay `null` while absent, with an unknown observation count represented as zero.
On the next successful observation, tracking begins at that scan's timestamp;
the record is not announced as newly discovered. Unknown dates are included by
`--ls 0` but cannot satisfy an age/date threshold. No old date is invented.

An absence means a record was not observed in this scan, not that its DNS
configuration was conclusively deleted. Output must be retained between runs;
starting from a text list begins a new history.

### Regression verification

`.github/workflows/linux-build.yml` builds the C++17 application with the pinned
submodules, runs C++ history/date/JSON-roundtrip tests, and exercises the real CLI
against a synthetic DNS server bound to loopback. It does not scan third-party
hosts. The C++ tests use explicit failure checks, including in release builds.
