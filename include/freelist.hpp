#pragma once

#include <algorithm>
#include <array>
#include <bit>
#include <cstdlib>
#include <expected>
#include <memory>
#include <span>
#include <utility>
#include <vector>

namespace memory {
    enum class AllocError {
        Success,
        OutOfMemory,
        InvalidAlignment,
        InvalidSize,
        DoubleFree,
        InvalidPointer
    };

    struct AllocatorConfig {
        size_t min_block_size = 16;
        size_t max_block_size = 1 << 20;
        size_t default_alignment = alignof(std::max_align_t);
        bool enable_coalescing = true;
        size_t initial_pool_size = 1 << 24;
        size_t pool_growth_factor = 2;
    };

    [[nodiscard]] static bool is_aligned(void* ptr, size_t alignment) noexcept {
        return alignment == 0 || (reinterpret_cast<uintptr_t>(ptr) % alignment == 0);
    }

    enum class BlockFlags : uint8_t { None = 0, Free = 1 << 0, Large = 1 << 1 };

    inline BlockFlags operator|(BlockFlags a, BlockFlags b) {
        return static_cast<BlockFlags>(std::to_underlying(a) | std::to_underlying(b));
    }
    inline BlockFlags operator&(BlockFlags a, BlockFlags b) {
        return static_cast<BlockFlags>(std::to_underlying(a) & std::to_underlying(b));
    }
    inline BlockFlags operator~(BlockFlags a) {
        return static_cast<BlockFlags>(~std::to_underlying(a));
    }
    inline BlockFlags operator^(BlockFlags a, BlockFlags b) {
        return static_cast<BlockFlags>(std::to_underlying(a) ^ std::to_underlying(b));
    }
    inline BlockFlags& operator&=(BlockFlags& a, BlockFlags b) {
        a = a & b;
        return a;
    }
    inline BlockFlags& operator^=(BlockFlags& a, BlockFlags b) {
        a = a ^ b;
        return a;
    }
    inline BlockFlags& operator|=(BlockFlags& a, BlockFlags b) {
        a = a | b;
        return a;
    }
    inline bool has_flag(BlockFlags flags, BlockFlags flag) {
        return (flags & flag) != BlockFlags::None;
    }

    class FreeListAllocator {
    private:
        struct BlockHeader {
            static constexpr uint64_t MAGIC = 0xDEADBEEFCAFEBABE;

            uint64_t magic = MAGIC;
            size_t size = 0;
            size_t alignment_shift = 0;
            BlockFlags flags = BlockFlags::None;
            BlockHeader* next = nullptr;

            [[nodiscard]] bool is_free() const noexcept {
                return has_flag(flags, BlockFlags::Free);
            }
            [[nodiscard]] bool is_large() const noexcept {
                return has_flag(flags, BlockFlags::Large);
            }
            [[nodiscard]] size_t alignment() const noexcept { return size_t(1) << alignment_shift; }
            [[nodiscard]] void* get_user_ptr() noexcept {
                return static_cast<void*>(reinterpret_cast<std::byte*>(this) + sizeof(BlockHeader) +
                                          sizeof(void*));
            }

            [[nodiscard]] static BlockHeader* from_user_ptr(void* ptr) noexcept {
                return reinterpret_cast<BlockHeader*>(reinterpret_cast<std::byte*>(ptr) -
                                                      sizeof(BlockHeader) - sizeof(void*));
            }

            static BlockHeader* create(void* location, size_t size, size_t align,
                                       BlockFlags flags) {
                auto* header = new (location)
                    BlockHeader{.magic = MAGIC,
                                .size = size,
                                .alignment_shift = static_cast<size_t>(std::countr_zero(align)),
                                .flags = flags,
                                .next = nullptr};
                return header;
            }
        };

        struct MemoryPool {
            void* memory = nullptr;
            size_t size = 0;

            MemoryPool() = default;
            explicit MemoryPool(size_t sz) : memory(std::malloc(sz)), size(sz) {}
            ~MemoryPool() {
                if (memory) std::free(memory);
            }

            MemoryPool(MemoryPool&& other) noexcept :
                memory(std::exchange(other.memory, nullptr)), size(std::exchange(other.size, 0)) {}

            MemoryPool& operator=(MemoryPool&& other) noexcept {
                if (this != &other) {
                    if (memory) std::free(memory);
                    memory = std::exchange(other.memory, nullptr);
                    size = std::exchange(other.size, 0);
                }
                return *this;
            }

            MemoryPool(const MemoryPool&) = delete;
            MemoryPool& operator=(const MemoryPool&) = delete;

            [[nodiscard]] bool contains(const void* ptr) const noexcept {
                auto* base = static_cast<const std::byte*>(memory);
                auto* p = static_cast<const std::byte*>(ptr);
                return p >= base && p < (base + size);
            }

            [[nodiscard]] std::span<std::byte> as_span() const noexcept {
                return {static_cast<std::byte*>(memory), size};
            }
        };

        struct LargeAlloc {
            void* base_ptr = nullptr;
            BlockHeader* header = nullptr;

            LargeAlloc() = default;
            LargeAlloc(void* base, BlockHeader* hdr) : base_ptr(base), header(hdr) {}
            ~LargeAlloc() {
                if (base_ptr) {
                    std::free(base_ptr);
                }
            }

            LargeAlloc(LargeAlloc&&) noexcept = default;
            LargeAlloc& operator=(LargeAlloc&& other) noexcept {
                if (this != &other) {
                    if (base_ptr) {
                        std::free(base_ptr);
                    }

                    base_ptr = std::exchange(other.base_ptr, nullptr);
                    header = std::exchange(other.header, nullptr);
                }
                return *this;
            }

            LargeAlloc(const LargeAlloc&) = delete;
            LargeAlloc& operator=(const LargeAlloc&) = delete;
        };

    public:
        explicit FreeListAllocator(AllocatorConfig config = {}) : m_config(config) {
            grow_pool(m_config.initial_pool_size);
        }

        ~FreeListAllocator() { release_all(); }

        FreeListAllocator(const FreeListAllocator&) = delete;
        FreeListAllocator& operator=(const FreeListAllocator&) = delete;

        FreeListAllocator(FreeListAllocator&& other) noexcept :
            m_config(other.m_config), m_pools(std::move(other.m_pools)),
            m_free_lists(std::move(other.m_free_lists)),
            m_large_allocs(std::move(other.m_large_allocs)),
            m_allocated_bytes(std::exchange(other.m_allocated_bytes, 0)),
            m_capacity_bytes(std::exchange(other.m_capacity_bytes, 0)) {}

        FreeListAllocator& operator=(FreeListAllocator&& other) noexcept {
            if (this != &other) {
                release_all();
                m_config = other.m_config;
                m_pools = std::move(other.m_pools);
                m_free_lists = std::move(other.m_free_lists);
                m_large_allocs = std::move(other.m_large_allocs);
                m_allocated_bytes = std::exchange(other.m_allocated_bytes, 0);
                m_capacity_bytes = std::exchange(other.m_capacity_bytes, 0);
            }
            return *this;
        }

        [[nodiscard]] std::expected<void*, AllocError> allocate(size_t size, size_t alignment = 0) {
            if (size == 0) {
                return std::unexpected(AllocError::InvalidSize);
            }
            if (alignment && !std::has_single_bit(alignment)) {
                return std::unexpected(AllocError::InvalidAlignment);
            }

            const size_t align = alignment ? alignment : m_config.default_alignment;
            if (size > m_config.max_block_size) {
                return allocate_large(size, align);
            }
            return allocate_small(size, align);
        }

        std::expected<void, AllocError> deallocate(void* ptr) noexcept {
            if (!ptr) {
                return {};
            }

            BlockHeader* header = BlockHeader::from_user_ptr(ptr);
            if (header->magic != BlockHeader::MAGIC) {
                return std::unexpected(AllocError::InvalidPointer);
            }
            if (header->is_free()) {
                return std::unexpected(AllocError::DoubleFree);
            }

            m_allocated_bytes -= header->size;
            if (header->is_large()) {
                auto it = std::find_if(
                    m_large_allocs.begin(), m_large_allocs.end(), [header](const LargeAlloc& la) {
                        return la.header == header;
                    });

                if (it != m_large_allocs.end()) {
                    m_capacity_bytes -= (header->size + sizeof(BlockHeader) + sizeof(void*) +
                                         header->alignment() - 1);
                    m_large_allocs.erase(it);
                    return {};
                }
                return std::unexpected(AllocError::InvalidPointer);
            } else {
                header->flags |= BlockFlags::Free;
                size_t sc = size_class(header->size);
                header->next = m_free_lists[sc];
                m_free_lists[sc] = header;
                if (m_config.enable_coalescing) {
                    coalesce(header);
                }
            }

            return {};
        }

        void release_all() noexcept {
            m_pools.clear();
            m_free_lists.fill(nullptr);
            m_large_allocs.clear();
            m_allocated_bytes = 0;
            m_capacity_bytes = 0;
        }

        [[nodiscard]] size_t allocated_bytes() const noexcept { return m_allocated_bytes; }
        [[nodiscard]] size_t capacity_bytes() const noexcept { return m_capacity_bytes; }
        [[nodiscard]] const AllocatorConfig& config() const noexcept { return m_config; }
        [[nodiscard]] std::span<const MemoryPool> memory_pools() const noexcept { return m_pools; }

    private:
        static constexpr size_t NUM_SIZE_CLASSES = 32;

        [[nodiscard]] size_t size_class(size_t size) const noexcept {
            size_t clamped = std::clamp(size, m_config.min_block_size, m_config.max_block_size);
            return std::bit_width(clamped) - std::bit_width(m_config.min_block_size);
        }

        bool grow_pool(size_t size) {
            size = std::max(size, m_config.initial_pool_size);
            MemoryPool pool(size);
            if (!pool.memory) {
                return false;
            }

            const size_t header_overhead = sizeof(BlockHeader) + sizeof(void*);
            const size_t usable_size = size - header_overhead;
            auto* header = BlockHeader::create(
                pool.memory, usable_size, m_config.default_alignment, BlockFlags::Free);

            size_t sc = size_class(usable_size);
            header->next = m_free_lists[sc];
            m_free_lists[sc] = header;

            m_pools.push_back(std::move(pool));
            m_capacity_bytes += size;
            return true;
        }

        [[nodiscard]] std::expected<void*, AllocError> allocate_small(size_t size, size_t align) {
            size_t sc = size_class(size);
            if (void* p = try_allocate_from_size_class(sc, align, size)) {
                return p;
            }

            for (size_t i = sc + 1; i < NUM_SIZE_CLASSES; ++i) {
                if (void* p = try_allocate_from_size_class(i, align, size)) {
                    return p;
                }
            }

            if (!grow_pool(m_capacity_bytes * m_config.pool_growth_factor)) {
                return std::unexpected(AllocError::OutOfMemory);
            }
            return allocate_small(size, align);
        }

        void* try_allocate_from_size_class(size_t sc, size_t align,
                                           size_t requested_size) noexcept {
            BlockHeader** pprev = &m_free_lists[sc];
            while (*pprev) {
                BlockHeader* header = *pprev;
                void* user_start = header->get_user_ptr();
                size_t available_space = header->size;
                void* aligned_ptr = user_start;
                if (!std::align(align, requested_size, aligned_ptr, available_space)) {
                    pprev = &header->next;
                    continue;
                }

                *pprev = header->next;
                header->flags = static_cast<BlockFlags>(header->flags & ~BlockFlags::Free);
                header->size = requested_size;
                m_allocated_bytes += requested_size;
                return user_start;
            }
            return nullptr;
        }

        [[nodiscard]] std::expected<void*, AllocError> allocate_large(size_t size, size_t align) {
            if (size == 0) {
                return std::unexpected(AllocError::InvalidSize);
            }
            if (!std::has_single_bit(align)) {
                return std::unexpected(AllocError::InvalidAlignment);
            }

            const size_t header_overhead = sizeof(BlockHeader) + sizeof(void*);
            const size_t total_size = size + header_overhead + align - 1;
            void* raw_memory = std::malloc(total_size);
            if (!raw_memory) {
                return std::unexpected(AllocError::OutOfMemory);
            }

            auto* header = BlockHeader::create(raw_memory, size, align, BlockFlags::Large);
            void* user_ptr = header->get_user_ptr();
            if (reinterpret_cast<uintptr_t>(user_ptr) % align != 0) {
                std::free(raw_memory);
                const size_t extra_space = align + header_overhead;
                raw_memory = std::malloc(size + extra_space);
                if (!raw_memory) {
                    return std::unexpected(AllocError::OutOfMemory);
                }

                uintptr_t raw_addr = reinterpret_cast<uintptr_t>(raw_memory);
                uintptr_t header_addr = (raw_addr + header_overhead + align - 1) & ~(align - 1);
                header_addr -= header_overhead;
                header = BlockHeader::create(
                    reinterpret_cast<void*>(header_addr), size, align, BlockFlags::Large);

                user_ptr = header->get_user_ptr();
            }

            m_large_allocs.emplace_back(raw_memory, header);
            m_allocated_bytes += size;
            m_capacity_bytes += total_size;

            return user_ptr;
        }

        void coalesce(BlockHeader* header) noexcept {
            std::byte* next_ptr =
                reinterpret_cast<std::byte*>(header) + sizeof(BlockHeader) + header->size;

            auto pool_contains = [next_ptr](const MemoryPool& pool) {
                return pool.contains(next_ptr);
            };

            if (auto it = std::find_if(m_pools.begin(), m_pools.end(), pool_contains);
                it != m_pools.end()) {
                auto* next = reinterpret_cast<BlockHeader*>(next_ptr);
                if (next->magic == BlockHeader::MAGIC && next->is_free() && !next->is_large() &&
                    next->alignment_shift == header->alignment_shift) {
                    remove_from_free_list(next);
                    header->size += sizeof(BlockHeader) + next->size;
                }
            }
        }

        void remove_from_free_list(BlockHeader* header) noexcept {
            if (header->is_large()) {
                return;
            }

            size_t sc = size_class(header->size);
            for (BlockHeader** pprev = &m_free_lists[sc]; *pprev; pprev = &(*pprev)->next) {
                if (*pprev == header) {
                    *pprev = header->next;
                    break;
                }
            }
        }

        AllocatorConfig m_config;
        std::vector<MemoryPool> m_pools;
        std::array<BlockHeader*, NUM_SIZE_CLASSES> m_free_lists = {};
        std::vector<LargeAlloc> m_large_allocs;
        size_t m_allocated_bytes = 0;
        size_t m_capacity_bytes = 0;
    };
}  // namespace memory
