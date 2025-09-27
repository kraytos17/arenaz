# arenaz - Allocator Implementations in C++

## Overview

`arenaz` provides custom memory allocator implementations in C++. It includes:
- Arena allocator ([include/arena.hpp](include/arena.hpp))
- Free list allocator ([include/freelist.hpp](include/freelist.hpp))
- Slab allocator ([include/slab.hpp](include/slab.hpp))

The project uses CMake for building and Catch2 (amalgamated) for unit testing.

## Features

- Slab Allocator (include/slab.hpp):
  - Header-only, type-aware slabs sized for T.
  - Template parameters: ObjectsPerSlab (default 64), MaxCachedEmptySlabs (default 2).
  - Fast allocate/deallocate, bulk helpers, simple stats(), optional debug poisoning with ARENAZ_DEBUG.
- FreeListAllocator (include/freelist.hpp):
  - Segregated free lists with configurable behavior via AllocatorConfig.
- Arena Allocator (include/arena.hpp):
  - Bump/linear allocation with fast resets.
- Tests with Catch2: see [tests/arena_test.cpp](tests/arena_test.cpp) and [tests/freelist_test.cpp](tests/freelist_test.cpp).
- Modern C++: C++23.

## Project Layout

- include/: Public headers (arena.hpp, freelist.hpp, slab.hpp)
- src/: App entry point and Catch2 amalgamated files (main.cpp, catch_amalgamated.*)
- tests/: Unit tests and test CMake configuration

## Building

Prerequisites: CMake ≥ 3.30, a C++23 compiler (GCC/Clang), and Make or Ninja.

```sh
git clone <repository_url>
cd arenaz
mkdir build && cd build
cmake ..
make   # or: ninja
```

This builds:
- App: build/arenaz
- Test executables (per file): build/tests/arena_test, build/tests/freelist_test

## Running Tests

From the build directory:
- Using CTest:
  ```sh
  ctest --output-on-failure
  ```
- Or directly:
  ```sh
  ./tests/arena_test
  ./tests/freelist_test
  ```

## License

MIT — see LICENSE.

Copyright (c) 2025 Soumil Kumar