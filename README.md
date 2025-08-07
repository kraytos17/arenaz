# arenaz - Allocator Implementations in C++

## Overview

`arenaz` is a C++ project focused on providing various custom memory allocator implementations.  It includes a [FreeListAllocator](include/freelist.hpp) and an [Arena](include/arena.hpp) allocator, designed to offer alternatives to the standard `new` and `delete` operators for specific use cases.  The project uses CMake for building and [Catch2](https://github.com/catchorg/Catch2) for unit testing.

## Features

*   **FreeListAllocator:** A segregated free list allocator that manages memory pools and large allocations, with optional coalescing of free blocks. Defined in [include/freelist.hpp](include/freelist.hpp).
*   **Arena Allocator:** (Currently only a header file exists - [include/arena.hpp](include/arena.hpp)) Intended to provide a simple and fast arena allocation strategy.
*   **Customizable Configuration:**  The [FreeListAllocator](include/freelist.hpp) is configurable via the [`AllocatorConfig`](include/freelist.hpp) struct, allowing users to tune the allocator's behavior.
*   **Comprehensive Unit Tests:**  Uses [Catch2](https://github.com/catchorg/Catch2) for thorough testing of allocator implementations. See [src/freelist_test.cpp](src/freelist_test.cpp) and [src/arena_test.cpp](src/arena_test.cpp).
*   **Modern C++:**  Written in C++23.

## Building the Project

These instructions will guide you through building the project using CMake.

### Prerequisites

*   CMake (version 3.30 or higher)
*   A C++23-compatible compiler (e.g., GCC, Clang)
*   Make or Ninja build tool

### Steps

1.  **Clone the repository:**

    ```sh
    git clone <repository_url>
    cd arenaz
    ```

2.  **Create a build directory:**

    ```sh
    mkdir build
    cd build
    ```

3.  **Configure the project with CMake:**

    ```sh
    cmake ..
    ```

4.  **Build the project:**

    ```sh
    make # or ninja
    ```

    This will create the `arenaz` and `arenaz_tests` executables inside the `build` directory.

## Running the Tests

To execute the unit tests, run the `arenaz_tests` executable located in the `build` directory:

```sh
./arenaz_tests
```

## Lisence

This project is licensed under the MIT License - see the LICENSE file for details.

Copyright (c) 2025 Soumil Kumar