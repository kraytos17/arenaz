#pragma once

#include <algorithm>
#include <bit>
#include <cassert>
#include <cstddef>
#include <expected>
#include <optional>
#include <print>
#include <source_location>
#include <span>
#include <string_view>
#include <unordered_map>
#include <utility>

#define _DEBUG 1
namespace ranges = std::ranges;

namespace memory {
    /// @brief Memory initialization policy for the arena
    enum class InitPolicy : uint8_t {
        Uninitialized,  ///< Leave memory as-is (fastest but potentially unsafe)
        Zeroed,  ///< Initialize memory to zero
        DebugPattern  ///< Initialize memory with debug pattern (0xAA)
    };

    /// @brief Strategy for handling alignment requests
    enum class AlignmentStrategy : uint8_t {
        Strict,  ///< Always honor requested alignment (may waste space)
        Optimistic,  ///< Use requested alignment but cap at arena's alignment
        Packed  ///< Use minimal alignment (most space efficient)
    };

    /// @brief Possible allocation error conditions
    enum class AllocError {
        OutOfMemory,  ///< Not enough space in arena
        InvalidAlignment,  ///< Requested alignment isn't power of two
        InvalidSize  ///< Requested size is zero
    };

    /// @brief Configuration for StackArena behavior
    struct Config {
        InitPolicy init_policy = InitPolicy::Uninitialized;
        AlignmentStrategy alignment_strategy = AlignmentStrategy::Optimistic;
        bool track_stats = false;  ///< Enable allocation statistics tracking
        bool debug_checks = true;  ///< Enable debug checks and poisoning
        std::source_location creation_location = std::source_location::current();

        /// @brief Set the memory initialization policy
        /// @param policy The initialization policy to use
        /// @return Reference to self for fluent chaining
        constexpr auto&& with_init_policy(this auto&& self, InitPolicy policy) noexcept {
            self.init_policy = policy;
            return std::forward<decltype(self)>(self);
        }

        /// @brief Set the alignment handling strategy
        /// @param strategy The alignment strategy to use
        /// @return Reference to self for fluent chaining
        constexpr auto&& with_alignment_strategy(this auto&& self,
                                                 AlignmentStrategy strategy) noexcept {
            self.alignment_strategy = strategy;
            return std::forward<decltype(self)>(self);
        }

        /// @brief Enable or disable statistics tracking
        /// @param enable Whether to track statistics (default true)
        /// @return Reference to self for fluent chaining
        constexpr auto&& with_statstracking(this auto&& self, bool enable = true) noexcept {
            self.track_stats = enable;
            return std::forward<decltype(self)>(self);
        }

        /// @brief Enable or disable debug checks
        /// @param enable Whether to enable debug checks (default true)
        /// @return Reference to self for fluent chaining
        constexpr auto&& with_debug_checks(this auto&& self, bool enable = true) noexcept {
            self.debug_checks = enable;
            return std::forward<decltype(self)>(self);
        }
    };

    /// @brief Allocation statistics tracking
    struct Stats {
        size_t total_allocated = 0;  ///< Total bytes allocated
        size_t peak_usage = 0;  ///< Maximum simultaneous usage
        size_t allocation_count = 0;  ///< Total allocation operations
        size_t deallocation_count = 0;  ///< Total deallocation operations
        size_t alignment_padding = 0;  ///< Total padding for alignment
        size_t largest_allocation = 0;  ///< Largest single allocation
        size_t fragmentation_waste = 0;  ///< Wasted space due to fragmentation
        std::unordered_map<size_t, std::string_view> allocation_tags;  ///< Allocation tags

        /// @brief Get current number of active allocations
        [[nodiscard]] constexpr size_t active_allocations() const noexcept {
            return allocation_count - deallocation_count;
        }

        /// @brief Calculate fragmentation ratio (waste/total)
        [[nodiscard]] constexpr double fragmentation_ratio() const noexcept {
            return total_allocated > 0 ? static_cast<double>(fragmentation_waste) / total_allocated
                                       : 0.0;
        }
    };

    /// @brief Represents a memory allocation from the arena
    struct Allocation {
        void* ptr;  ///< Pointer to allocated memory
        size_t size;  ///< Size of allocation in bytes
        size_t alignment;  ///< Actual alignment used
        size_t padding;  ///< Padding bytes for alignment
        std::string_view tag;  ///< Optional allocation tag
    };

    /// @brief Stack-based memory arena allocator
    /// @tparam SIZE Total size of the arena in bytes
    /// @tparam ALIGNMENT Alignment of the arena buffer (must be power of two)
    template<size_t SIZE, size_t ALIGNMENT = 64>
    class StackArena {
        static_assert(SIZE > 0, "Arena size must be greater than zero");
        static_assert(std::has_single_bit(ALIGNMENT), "Alignment must be a power of two");
        static_assert(ALIGNMENT <= 4096, "Alignment too large (max 4096 bytes)");

    public:
        static constexpr size_t capacity = SIZE;  ///< Total arena capacity
        static constexpr size_t buffer_alignment = ALIGNMENT;  ///< Buffer alignment

        /// @brief Construct a StackArena with configuration
        /// @param config Configuration for arena behavior
        explicit StackArena(Config config = {}) :
            m_config(std::move(config)),
            m_stats(m_config.track_stats ? std::make_optional<Stats>() : std::nullopt) {
            if (m_config.debug_checks) {
                poison_memory(m_buffer, SIZE, std::byte{0xAA});
            }
        }

        /// @brief Destructor checks for leaks if debug checks enabled
        ~StackArena() noexcept {
            if (m_config.debug_checks) {
                report_leaks();
            }
        }

        StackArena(const StackArena&) = delete;
        StackArena& operator=(const StackArena&) = delete;
        StackArena(StackArena&&) noexcept = default;
        StackArena& operator=(StackArena&&) noexcept = default;

        /// @brief Allocate memory from the arena
        /// @param size Number of bytes to allocate
        /// @param alignment Requested alignment (must be power of two)
        /// @param tag Optional tag for tracking
        /// @return Allocation info or error
        [[nodiscard]]
        std::expected<Allocation, AllocError> allocate(size_t size,
                                                       size_t alignment = default_alignment(),
                                                       std::string_view tag = "") noexcept {
            if (size == 0) {
                return std::unexpected(AllocError::InvalidSize);
            }
            if (!std::has_single_bit(alignment)) {
                return std::unexpected(AllocError::InvalidAlignment);
            }

            const size_t effective_alignment = resolve_alignment(alignment);
            const size_t current = m_offset;
            const size_t aligned_offset = align_up(current, effective_alignment);
            const size_t padding = aligned_offset - current;

            if (aligned_offset + size > SIZE) {
                return std::unexpected(AllocError::OutOfMemory);
            }

            void* ptr = m_buffer + aligned_offset;
            m_offset = aligned_offset + size;

            maybe_initialize(ptr, size);
            update_allocation_stats(size, padding, aligned_offset, tag);

            return Allocation{ptr, size, effective_alignment, padding, tag};
        }

        /// @brief Deallocate memory (doesn't actually free, just runs destructors)
        /// @tparam T Type of object being deallocated
        /// @param ptr Pointer to memory to deallocate
        template<typename T>
        void deallocate(T* ptr) noexcept {
            if (!ptr) {
                return;
            }
            if constexpr (!std::is_trivially_destructible_v<T>) {
                std::destroy_at(ptr);
            }
            if (m_config.debug_checks) {
                poison_memory(ptr, sizeof(T), std::byte{0xFD});
            }
            if (m_stats) {
                m_stats->deallocation_count++;
            }
        }

        /// @brief Reset the arena to empty state
        /// @param policy Memory initialization policy for reset
        void reset(InitPolicy policy = InitPolicy::Uninitialized) noexcept {
            if (m_config.debug_checks) {
                report_leaks();
            }

            switch (policy) {
                case InitPolicy::Zeroed:
                    poison_memory(m_buffer, SIZE, std::byte{0});
                    break;
                case InitPolicy::DebugPattern:
                    poison_memory(m_buffer, SIZE, std::byte{0xAA});
                    break;
                case InitPolicy::Uninitialized:
                    break;
            }

            m_offset = 0;
            if (m_stats) {
                *m_stats = Stats{};
            }
        }

        // Getters
        [[nodiscard]] constexpr size_t used() const noexcept { return m_offset; }
        [[nodiscard]] constexpr size_t get_capacity() const noexcept { return SIZE; }
        [[nodiscard]] constexpr size_t available() const noexcept { return SIZE - m_offset; }
        [[nodiscard]] constexpr size_t get_alignment() const noexcept { return ALIGNMENT; }
        [[nodiscard]] const Stats* stats() const noexcept { return m_stats ? &*m_stats : nullptr; }

        /// @brief Construct an object in the arena
        /// @tparam T Type of object to construct
        /// @tparam Args Argument types for constructor
        /// @param args Arguments for constructor
        /// @return Pointer to constructed object or nullptr on failure
        template<typename T, typename... Args>
        [[nodiscard]] T* make(Args&&... args) noexcept(
            std::is_nothrow_constructible_v<T, Args...>) {
            auto alloc = allocate(sizeof(T), alignof(T), typeid(T).name());
            if (!alloc) {
                return nullptr;
            }
            try {
                return new (alloc->ptr) T(std::forward<Args>(args)...);
            } catch (...) {
                m_offset -= alloc->size;
                return nullptr;
            }
        }

        /// @brief Destroy an object in the arena
        /// @tparam T Type of object to destroy
        /// @param obj Pointer to object to destroy
        template<typename T>
        void destroy(T* obj) noexcept {
            if (!obj) {
                return;
            }

            if (m_config.debug_checks) {
                if (!owns(obj)) {
                    std::println(stderr,
                                 "Warning: StackArena<{}, {}>::destroy called on invalid or "
                                 "non-owned pointer\n  Location: {}:{}",
                                 SIZE,
                                 ALIGNMENT,
                                 m_config.creation_location.file_name(),
                                 m_config.creation_location.line());
                    return;
                }

                auto* bytes = reinterpret_cast<std::byte*>(obj);
                if (ranges::all_of(std::span{bytes, sizeof(T)},
                                   [](std::byte b) { return b == std::byte{0xFD}; })) {
                    std::println(stderr,
                                 "Warning: StackArena<{}, {}>::destroy called twice on same object",
                                 SIZE,
                                 ALIGNMENT);
                    return;
                }
            }

            if constexpr (!std::is_trivially_destructible_v<T>) {
                std::destroy_at(obj);
            }

            if (m_config.debug_checks) {
                poison_memory(obj, sizeof(T), std::byte{0xFD});
            }

            if (m_stats) {
                m_stats->deallocation_count++;
            }
        }

        /// @brief Print statistics to stdout
        void dump_stats() const {
            if (!m_stats) {
                return;
            }
            std::println("StackArena<{}, {}> Statistics:", SIZE, ALIGNMENT);
            std::println("  Capacity: {} bytes", SIZE);
            std::println("  Used: {} bytes ({:.1f}%)",
                         m_stats->total_allocated,
                         100.0 * m_stats->total_allocated / SIZE);
            std::println("  Peak Usage: {} bytes", m_stats->peak_usage);
            std::println("  Active Allocations: {}", m_stats->active_allocations());
            std::println("  Buffer Alignment: {} bytes", ALIGNMENT);
            if (!m_stats->allocation_tags.empty()) {
                std::println("  Allocation Tags:");
                for (const auto& [offset, tag]: m_stats->allocation_tags) {
                    std::println("    - {} @ offset {}", tag, offset);
                }
            }
        }

        [[nodiscard]] const void* buffer_address() const noexcept { return m_buffer; }

        /// @brief Check if pointer belongs to this arena
        /// @param ptr Pointer to check
        /// @return True if pointer is within arena's memory range
        [[nodiscard]] bool owns(const void* ptr) const noexcept {
            const auto addr = reinterpret_cast<uintptr_t>(ptr);
            const auto start = reinterpret_cast<uintptr_t>(m_buffer);
            const auto end = start + SIZE;

            return addr >= start && addr < end;
        }

    private:
        alignas(ALIGNMENT) std::byte m_buffer[SIZE];  ///< Backing memory buffer
        size_t m_offset = 0;  ///< Current allocation offset
        Config m_config;  ///< Configuration
        std::optional<Stats> m_stats;  ///< Optional statistics

        /// @brief Get default alignment (max_align_t)
        static constexpr size_t default_alignment() noexcept { return alignof(std::max_align_t); }

        /// @brief Align value up to given alignment
        static constexpr size_t align_up(size_t value, size_t alignment) noexcept {
            return (value + alignment - 1) & ~(alignment - 1);
        }

        /// @brief Resolve actual alignment based on strategy
        size_t resolve_alignment(size_t requested) const noexcept {
            switch (m_config.alignment_strategy) {
                case AlignmentStrategy::Strict:
                    return requested;
                case AlignmentStrategy::Optimistic:
                    return std::min(requested, ALIGNMENT);
                case AlignmentStrategy::Packed:
                    return alignof(std::max_align_t);
                default:
                    std::unreachable();
            }
        }

        /// @brief Initialize memory based on policy
        void maybe_initialize(void* ptr, size_t size) noexcept {
            switch (m_config.init_policy) {
                case InitPolicy::Zeroed:
                    poison_memory(ptr, size, std::byte{0});
                    break;
                case InitPolicy::DebugPattern:
                    poison_memory(ptr, size, std::byte{0xAA});
                    break;
                case InitPolicy::Uninitialized:
                    break;
            }
        }

        /// @brief Fill memory with pattern (for debug or initialization)
        void poison_memory(void* ptr, size_t size, std::byte pattern) noexcept {
            ranges::fill(std::span{static_cast<std::byte*>(ptr), size}, pattern);
        }

        /// @brief Update statistics if tracking enabled
        void update_allocation_stats(size_t size, size_t padding, size_t offset,
                                     std::string_view tag) noexcept {
            if (!m_stats) {
                return;
            }

            auto& s = *m_stats;
            s.total_allocated += size;
            s.allocation_count++;
            s.peak_usage = std::max(s.peak_usage, m_offset);
            s.largest_allocation = std::max(s.largest_allocation, size);
            s.alignment_padding += padding;
            s.fragmentation_waste += padding;
            if (m_config.debug_checks && !tag.empty()) {
                s.allocation_tags.emplace(offset, tag);
            }
        }

        /// @brief Report memory leaks if any active allocations remain
        void report_leaks() const noexcept {
            if (m_stats && m_stats->active_allocations() > 0) {
                std::println(stderr,
                             "Warning: StackArena<{}, {}> destroyed with {} active "
                             "allocations\nCreated at: {}:{}",
                             SIZE,
                             ALIGNMENT,
                             m_stats->active_allocations(),
                             m_config.creation_location.file_name(),
                             m_config.creation_location.line());
            }
        }
    };

    // Common arena size/alignment presets
    template<size_t SIZE>
    using Arena8 = StackArena<SIZE, 8>;

    template<size_t SIZE>
    using Arena16 = StackArena<SIZE, 16>;

    template<size_t SIZE>
    using Arena32 = StackArena<SIZE, 32>;

    template<size_t SIZE>
    using Arena64 = StackArena<SIZE, 64>;

    template<size_t SIZE>
    using Arena128 = StackArena<SIZE, 128>;

    template<size_t SIZE>
    using Arena256 = StackArena<SIZE, 256>;

    // Common arena presets
    using SmallArena = StackArena<1024, 16>;
    using MediumArena = StackArena<64 * 1024, 32>;
    using LargeArena = StackArena<1024 * 1024, 64>;
    using HugeArena = StackArena<16 * 1024 * 1024, 128>;

    /// @brief Create a StackArena with given size and alignment
    /// @tparam SIZE Size of arena in bytes
    /// @tparam ALIGNMENT Alignment of arena (default 64)
    /// @param config Configuration for arena
    /// @return Constructed StackArena
    template<size_t SIZE, size_t ALIGNMENT = 64>
    [[nodiscard]] constexpr auto make_stack_arena(Config config = {}) {
        return StackArena<SIZE, ALIGNMENT>{std::move(config)};
    }
}  // namespace memory
