# Benchmark scope

`make bench-compare CC=gcc` builds and runs the Goose, libcurl, Node.js and Python drivers that are installed. It makes no network request. The core library itself needs no native dependency; the comparison drivers need a C compiler with POSIX monotonic-clock support, pkg-config/libcurl and Node.js.

Each driver performs 100,000 operations on a fixed input per workload. Three measured process samples follow one excluded warmup process, with driver order rotated. Timing uses each driver's monotonic loop clock and excludes process startup. Results retain commands, raw outputs, checksums, source hashes, tool versions, compiler transcripts and machine details.

The operations do different work. Goose views borrow data; owned parsing copies it; resolution reuses a parsed base. CURLU reparses the base on every resolution. Node uses WHATWG URL behavior in a new process per sample. Python's URL split cache remains enabled. Checksums and validation differ by driver. Compare a workload only with itself across runs; these numbers do not rank URL libraries.

The recorded [sample](RESULTS.md) links all raw observations and documents the measured source match to current main.
