#include "../include/freelist.hpp"

#include "catch_amalgamated.hpp"

using namespace memory;

TEST_CASE("FreeListAllocator basic functionality", "[freelist]") {
    FreeListAllocator allocator;

    SECTION("Basic allocation and deallocation") {
        auto ptr = allocator.allocate(64);
        REQUIRE(ptr.has_value());
        REQUIRE(ptr.value() != nullptr);

        auto result = allocator.deallocate(ptr.value());
        REQUIRE(result.has_value());
    }

    SECTION("Allocation with different sizes") {
        auto small = allocator.allocate(16);
        auto medium = allocator.allocate(256);
        auto large = allocator.allocate(1024);

        REQUIRE(small.has_value());
        REQUIRE(medium.has_value());
        REQUIRE(large.has_value());

        REQUIRE(allocator.deallocate(small.value()).has_value());
        REQUIRE(allocator.deallocate(medium.value()).has_value());
        REQUIRE(allocator.deallocate(large.value()).has_value());
    }

    SECTION("Alignment requirements") {
        auto ptr1 = allocator.allocate(64, 16);
        auto ptr2 = allocator.allocate(128, 64);

        REQUIRE(ptr1.has_value());
        REQUIRE(ptr2.has_value());

        REQUIRE(reinterpret_cast<uintptr_t>(ptr1.value()) % 16 == 0);
        REQUIRE(reinterpret_cast<uintptr_t>(ptr2.value()) % 64 == 0);

        REQUIRE(allocator.deallocate(ptr1.value()).has_value());
        REQUIRE(allocator.deallocate(ptr2.value()).has_value());
    }
}

TEST_CASE("FreeListAllocator error handling", "[freelist]") {
    FreeListAllocator allocator;

    SECTION("Invalid allocation sizes") {
        auto zero = allocator.allocate(0);
        REQUIRE_FALSE(zero.has_value());
        REQUIRE(zero.error() == AllocError::InvalidSize);
    }

    SECTION("Invalid alignment") {
        auto unaligned = allocator.allocate(64, 24);
        REQUIRE_FALSE(unaligned.has_value());
        REQUIRE(unaligned.error() == AllocError::InvalidAlignment);
    }

    SECTION("Double free detection") {
        auto ptr = allocator.allocate(64);
        REQUIRE(ptr.has_value());

        auto result1 = allocator.deallocate(ptr.value());
        REQUIRE(result1.has_value());

        auto result2 = allocator.deallocate(ptr.value());
        REQUIRE_FALSE(result2.has_value());
        REQUIRE(result2.error() == AllocError::DoubleFree);
    }

    SECTION("Invalid pointer detection") {
        int x;
        auto result = allocator.deallocate(&x);
        REQUIRE_FALSE(result.has_value());
        REQUIRE(result.error() == AllocError::InvalidPointer);
    }
}

TEST_CASE("FreeListAllocator memory management", "[freelist]") {
    FreeListAllocator allocator;

    SECTION("Memory reuse") {
        auto ptr1 = allocator.allocate(128);
        REQUIRE(ptr1.has_value());

        auto result = allocator.deallocate(ptr1.value());
        REQUIRE(result.has_value());

        auto ptr2 = allocator.allocate(128);
        REQUIRE(ptr2.has_value());
        REQUIRE(ptr1.value() == ptr2.value());
        REQUIRE(allocator.deallocate(ptr2.value()).has_value());
    }

    SECTION("Block splitting") {
        auto ptr = allocator.allocate(allocator.config().min_block_size * 4);
        REQUIRE(ptr.has_value());
        REQUIRE(allocator.deallocate(ptr.value()).has_value());

        auto ptr1 = allocator.allocate(allocator.config().min_block_size);
        auto ptr2 = allocator.allocate(allocator.config().min_block_size);
        REQUIRE(ptr1.has_value());
        REQUIRE(ptr2.has_value());

        REQUIRE(allocator.deallocate(ptr1.value()).has_value());
        REQUIRE(allocator.deallocate(ptr2.value()).has_value());
    }

    SECTION("Coalescing") {
        auto config = allocator.config();
        config.enable_coalescing = true;
        FreeListAllocator coalescing_alloc(config);

        auto ptr1 = coalescing_alloc.allocate(config.min_block_size);
        auto ptr2 = coalescing_alloc.allocate(config.min_block_size);
        auto ptr3 = coalescing_alloc.allocate(config.min_block_size);
        REQUIRE(ptr1.has_value());
        REQUIRE(ptr2.has_value());
        REQUIRE(ptr3.has_value());

        REQUIRE(coalescing_alloc.deallocate(ptr3.value()).has_value());
        REQUIRE(coalescing_alloc.deallocate(ptr2.value()).has_value());
        REQUIRE(coalescing_alloc.deallocate(ptr1.value()).has_value());

        auto large_ptr = coalescing_alloc.allocate(config.min_block_size * 3);
        REQUIRE(large_ptr.has_value());
        REQUIRE(coalescing_alloc.deallocate(large_ptr.value()).has_value());
    }
}

TEST_CASE("FreeListAllocator large allocations", "[freelist]") {
    FreeListAllocator allocator;
    const size_t large_size = allocator.config().max_block_size * 2;

    SECTION("Large allocation works") {
        auto ptr = allocator.allocate(large_size);
        REQUIRE(ptr.has_value());
        REQUIRE(ptr.value() != nullptr);

        auto result = allocator.deallocate(ptr.value());
        REQUIRE(result.has_value());
    }

    SECTION("Large allocation alignment") {
        auto ptr = allocator.allocate(large_size, 64);
        REQUIRE(ptr.has_value());
        REQUIRE(reinterpret_cast<uintptr_t>(ptr.value()) % 64 == 0);

        REQUIRE(allocator.deallocate(ptr.value()).has_value());
    }
}

TEST_CASE("FreeListAllocator statistics", "[freelist]") {
    FreeListAllocator allocator;
    const size_t block_size = 64;

    SECTION("Allocated bytes tracking") {
        REQUIRE(allocator.allocated_bytes() == 0);

        auto ptr1 = allocator.allocate(block_size);
        REQUIRE(ptr1.has_value());
        REQUIRE(allocator.allocated_bytes() >= block_size);

        auto ptr2 = allocator.allocate(block_size * 2);
        REQUIRE(ptr2.has_value());
        REQUIRE(allocator.allocated_bytes() >= block_size * 3);

        REQUIRE(allocator.deallocate(ptr1.value()).has_value());
        REQUIRE(allocator.allocated_bytes() >= block_size * 2);

        REQUIRE(allocator.deallocate(ptr2.value()).has_value());
        REQUIRE(allocator.allocated_bytes() == 0);
    }

    SECTION("Capacity tracking") {
        size_t initial_capacity = allocator.capacity_bytes();
        REQUIRE(initial_capacity > 0);

        std::vector<void*> ptrs;
        while (true) {
            auto ptr = allocator.allocate(allocator.config().min_block_size);
            if (!ptr) break;
            ptrs.push_back(ptr.value());
        }

        REQUIRE(allocator.capacity_bytes() > initial_capacity);
        for (auto ptr: ptrs) {
            REQUIRE(allocator.deallocate(ptr).has_value());
        }
    }
}

TEST_CASE("FreeListAllocator configuration", "[freelist]") {
    SECTION("Custom configuration") {
        AllocatorConfig config;
        config.min_block_size = 32;
        config.max_block_size = 1 << 16;
        config.initial_pool_size = 1 << 20;

        FreeListAllocator allocator(config);

        REQUIRE(allocator.config().min_block_size == 32);
        REQUIRE(allocator.config().max_block_size == 1 << 16);

        auto ptr = allocator.allocate(16);
        REQUIRE(ptr.has_value());
        REQUIRE(allocator.deallocate(ptr.value()).has_value());
    }
}

TEST_CASE("FreeListAllocator move semantics", "[freelist]") {
    FreeListAllocator allocator1;

    auto ptr = allocator1.allocate(64);
    REQUIRE(ptr.has_value());

    size_t allocated = allocator1.allocated_bytes();
    size_t capacity = allocator1.capacity_bytes();

    SECTION("Move construction") {
        FreeListAllocator allocator2(std::move(allocator1));

        REQUIRE(allocator2.allocated_bytes() == allocated);
        REQUIRE(allocator2.capacity_bytes() == capacity);
        REQUIRE(allocator2.deallocate(ptr.value()).has_value());
    }

    SECTION("Move assignment") {
        FreeListAllocator allocator2;
        allocator2 = std::move(allocator1);

        REQUIRE(allocator2.allocated_bytes() == allocated);
        REQUIRE(allocator2.capacity_bytes() == capacity);
        REQUIRE(allocator2.deallocate(ptr.value()).has_value());
    }
}

TEST_CASE("FreeListAllocator pool inspection", "[freelist]") {
    FreeListAllocator allocator;

    SECTION("Memory pools access") {
        auto pools = allocator.memory_pools();
        REQUIRE_FALSE(pools.empty());
        REQUIRE(pools[0].size >= allocator.config().initial_pool_size);
    }

    SECTION("Pool contains check") {
        auto ptr = allocator.allocate(64);
        REQUIRE(ptr.has_value());

        bool found = false;
        for (const auto& pool: allocator.memory_pools()) {
            if (pool.contains(ptr.value())) {
                found = true;
                break;
            }
        }

        REQUIRE(found);
        REQUIRE(allocator.deallocate(ptr.value()).has_value());
    }
}
