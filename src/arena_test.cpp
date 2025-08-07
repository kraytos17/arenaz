#include "../include/arena.hpp"

#include "catch_amalgamated.hpp"

using namespace memory;

TEST_CASE("StackArena basic functionality", "[arena]") {
    constexpr size_t arena_size = 1024;
    auto arena = make_stack_arena<arena_size>();

    SECTION("Initial state") {
        REQUIRE(arena.get_capacity() == arena_size);
        REQUIRE(arena.used() == 0);
        REQUIRE(arena.available() == arena_size);
        REQUIRE(arena.stats() == nullptr);
    }

    SECTION("Simple allocation") {
        auto alloc = arena.allocate(64);
        REQUIRE(alloc.has_value());
        REQUIRE(alloc->ptr != nullptr);
        REQUIRE(alloc->size == 64);
        REQUIRE(arena.used() == 64);
        REQUIRE(arena.available() == arena_size - 64);
    }

    SECTION("Allocation too large") {
        auto alloc = arena.allocate(arena_size + 1);
        REQUIRE_FALSE(alloc.has_value());
        REQUIRE(alloc.error() == AllocError::OutOfMemory);
    }

    SECTION("Zero-sized allocation") {
        auto alloc = arena.allocate(0);
        REQUIRE_FALSE(alloc.has_value());
        REQUIRE(alloc.error() == AllocError::InvalidSize);
    }

    SECTION("Invalid alignment") {
        auto alloc = arena.allocate(64, 3);
        REQUIRE_FALSE(alloc.has_value());
        REQUIRE(alloc.error() == AllocError::InvalidAlignment);
    }

    SECTION("Type-safe allocation") {
        struct TestStruct {
            int x;
            float y;
        };

        auto* obj = arena.make<TestStruct>(42, 3.14f);
        REQUIRE(obj != nullptr);
        REQUIRE(obj->x == 42);
        REQUIRE(obj->y == Catch::Approx(3.14f));
        REQUIRE(arena.used() == sizeof(TestStruct));

        arena.destroy(obj);
        REQUIRE(arena.available() == arena_size - sizeof(TestStruct));
    }

    SECTION("Alignment strategies") {
        auto config = Config{};
        auto strict_config = config.with_alignment_strategy(AlignmentStrategy::Strict);
        auto strict_arena = make_stack_arena<arena_size>(strict_config);

        auto alloc = strict_arena.allocate(64, 64);
        REQUIRE(alloc.has_value());
        REQUIRE(reinterpret_cast<uintptr_t>(alloc->ptr) % 64 == 0);

        config = Config{};
        auto packed_config = config.with_alignment_strategy(AlignmentStrategy::Packed);
        auto packed_arena = make_stack_arena<arena_size>(packed_config);

        alloc = packed_arena.allocate(64);
        REQUIRE(alloc.has_value());
        REQUIRE(reinterpret_cast<uintptr_t>(alloc->ptr) % alignof(std::max_align_t) == 0);
    }

    SECTION("Statistics tracking") {
        auto config = Config{};
        auto stats_arena = make_stack_arena<arena_size>(config.with_statstracking(true));
        auto alloc1 = stats_arena.allocate(64);
        auto alloc2 = stats_arena.allocate(128);

        const auto* stats = stats_arena.stats();
        REQUIRE(stats != nullptr);
        REQUIRE(stats->total_allocated == 64 + 128);
        REQUIRE(stats->allocation_count == 2);
        REQUIRE(stats->active_allocations() == 2);
        REQUIRE(stats->largest_allocation == 128);
    }

    SECTION("Debug tags") {
        auto config = Config{};
        auto debug_arena =
            make_stack_arena<arena_size>(config.with_debug_checks(true).with_statstracking(true));

        auto alloc1 = debug_arena.allocate(64, 8, "TestAllocation");
        auto alloc2 = debug_arena.allocate(128, 16, "AnotherAllocation");

        const auto* stats = debug_arena.stats();
        REQUIRE(stats != nullptr);
        REQUIRE(stats->allocation_tags.size() == 2);
    }

    SECTION("Reset behavior") {
        auto arena = make_stack_arena<arena_size>();
        auto alloc = arena.allocate(256);
        REQUIRE(arena.used() == 256);

        arena.reset();
        REQUIRE(arena.used() == 0);
        REQUIRE(arena.available() == arena_size);
    }

    SECTION("Memory poisoning") {
        auto arena = make_stack_arena<arena_size>(
            Config{}.with_init_policy(InitPolicy::DebugPattern).with_debug_checks(true));

        auto alloc = arena.allocate(64);
        auto* byte_ptr = static_cast<std::byte*>(alloc->ptr);
        REQUIRE(byte_ptr[0] == std::byte{0xAA});

        arena.deallocate(byte_ptr);
        REQUIRE(byte_ptr[0] == std::byte{0xFD});
    }

    SECTION("Ownership check") {
        auto alloc = arena.allocate(64);
        REQUIRE(arena.owns(alloc->ptr));

        int stack_var;
        REQUIRE_FALSE(arena.owns(&stack_var));
    }
}
