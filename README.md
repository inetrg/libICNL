# libICNL

_*Work in Progress*_

**libICNL** is the reference implemenation for [ICNLoWPAN](https://tools.ietf.org/html/draft-gundogan-icnrg-ccnlowpan-01).
This implementation compiles to a static library and can easily be integrated
into existing NDN and CCNx implementations.

To build this library, run `cmake` from within the `build` directory.
```sh
cd build
cmake ..
make
```

Currently, all static libraries reside in `build/lib`.
It is planned to provide a combined static library.
