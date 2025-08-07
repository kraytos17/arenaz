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
        arena.deallocate(static_cast<std::byte*>(alloc->ptr));
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

        stats_arena.deallocate(static_cast<std::byte*>(alloc1->ptr));
        stats_arena.deallocate(static_cast<std::byte*>(alloc2->ptr));
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

        debug_arena.deallocate(static_cast<std::byte*>(alloc1->ptr));
        debug_arena.deallocate(static_cast<std::byte*>(alloc2->ptr));
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

    SECTION("Peak usage and fragmentation tracking") {
        auto arena = make_stack_arena<arena_size>(Config{}.with_statstracking(true));

        auto a1 = arena.allocate(32, 32);
        auto a2 = arena.allocate(64, 64);
        auto a3 = arena.allocate(16, 16);

        const auto* stats = arena.stats();
        REQUIRE(stats != nullptr);
        REQUIRE(stats->peak_usage <= arena_size);
        REQUIRE(stats->fragmentation_waste >= stats->alignment_padding);
        REQUIRE(stats->alignment_padding > 0);

        arena.deallocate(static_cast<std::byte*>(a1->ptr));
        arena.deallocate(static_cast<std::byte*>(a2->ptr));
        arena.deallocate(static_cast<std::byte*>(a3->ptr));
    }

    SECTION("Multiple object construction and destruction") {
        struct Dummy {
            int val = 0;
            Dummy(int v) : val(v) {}
            ~Dummy() { val = -1; }
        };

        auto arena = make_stack_arena<arena_size>();
        Dummy* objs[10];

        for (int i = 0; i < 10; ++i) {
            objs[i] = arena.make<Dummy>(i);
            REQUIRE(objs[i] != nullptr);
            REQUIRE(objs[i]->val == i);
        }

        for (int i = 0; i < 10; ++i) {
            arena.destroy(objs[i]);
        }
    }

    SECTION("Reset with specific policy - Zeroed") {
        auto arena = make_stack_arena<arena_size>();
        auto alloc = arena.allocate(128);
        auto* ptr = static_cast<std::byte*>(alloc->ptr);
        std::fill_n(ptr, 128, std::byte{0xFF});

        arena.reset(InitPolicy::Zeroed);
        auto alloc2 = arena.allocate(128);
        auto* ptr2 = static_cast<std::byte*>(alloc2->ptr);
        REQUIRE(ptr2[0] == std::byte{0});
    }

    SECTION("Non-trivially destructible object is destroyed correctly") {
        struct Complex {
            bool* destroyed;
            ~Complex() { *destroyed = true; }
        };

        bool was_destroyed = false;
        auto arena = make_stack_arena<arena_size>();
        auto* obj = arena.make<Complex>(&was_destroyed);
        arena.destroy(obj);
        REQUIRE(was_destroyed);
    }

    SECTION("Double deallocation does not crash or corrupt stats") {
        auto arena = make_stack_arena<arena_size>(Config{}.with_statstracking(true));
        auto* obj = arena.make<int>(123);

        arena.destroy(obj);
        REQUIRE_NOTHROW(arena.destroy(obj));

        const auto* stats = arena.stats();
        REQUIRE(stats->allocation_count == 1);
        REQUIRE(stats->deallocation_count == 1);
    }

    SECTION("Large alignment handling") {
        constexpr size_t large_align = 256;
        auto config = Config{}.with_alignment_strategy(AlignmentStrategy::Strict);
        auto arena = make_stack_arena<arena_size, large_align>(config);

        auto alloc = arena.allocate(64, large_align);
        REQUIRE(alloc.has_value());
        REQUIRE(reinterpret_cast<uintptr_t>(alloc->ptr) % large_align == 0);
    }

    SECTION("Minimal alignment with Packed strategy") {
        auto arena = make_stack_arena<arena_size>(
            Config{}.with_alignment_strategy(AlignmentStrategy::Packed));

        auto alloc = arena.allocate(64);
        REQUIRE(alloc.has_value());
        REQUIRE(reinterpret_cast<uintptr_t>(alloc->ptr) % alignof(std::max_align_t) == 0);
    }

    SECTION("Pointer ownership at boundaries") {
        auto alloc = arena.allocate(64);
        REQUIRE(alloc.has_value());

        auto* ptr = static_cast<std::byte*>(alloc->ptr);
        REQUIRE(arena.owns(ptr));

        auto* end_ptr = ptr + alloc->size - 1;
        REQUIRE(arena.owns(end_ptr));

        auto* beyond_arena = static_cast<const std::byte*>(arena.buffer_address()) + arena_size;
        REQUIRE_FALSE(arena.owns(beyond_arena));
    }

    SECTION("Tagged allocations are preserved") {
        auto arena =
            make_stack_arena<arena_size>(Config{}.with_statstracking(true).with_debug_checks(true));

        auto alloc = arena.allocate(32, 16, "MyTaggedAlloc");
        const auto* stats = arena.stats();
        REQUIRE(stats->allocation_tags.size() == 1);
        REQUIRE(stats->allocation_tags.begin()->second == "MyTaggedAlloc");
    }
}
