#pragma once

#include <algorithm>
#include <array>
#include <cassert>
#include <cstddef>
#include <memory>
#include <new>
#include <vector>

#ifdef ARENAZ_DEBUG
#include <cstring>
#endif

namespace arenaz {
    template<typename T, size_t ObjectsPerSlab = 64>
    class SlabAllocator {
    private:
        struct FreeNode {
            FreeNode* next;
        };

        struct Slab {
            static constexpr std::size_t slot_size() noexcept {
                return std::max(sizeof(T), sizeof(FreeNode));
            }

            Slab* next;
            FreeNode* free_list;
            size_t free_cnt;
            alignas(T) std::array<std::byte, ObjectsPerSlab * slot_size()> data;
        };

        Slab* m_partial = nullptr;
        Slab* m_full = nullptr;
        Slab* m_empty = nullptr;

        size_t m_total_slabs = 0;
        size_t m_active_slabs = 0;
        size_t m_live_objects = 0;
        size_t m_peak_objects = 0;

    public:
        struct Stats {
            size_t total_slabs;
            size_t active_slabs;
            size_t live_objects;
            size_t peak_objects;
        };

        SlabAllocator() noexcept = default;
        ~SlabAllocator() noexcept {
#ifdef ARENAZ_DEBUG
            if (m_live_objects != 0) {
                assert(false && "SlabAllocator destroyed with live objects still allocated!");
            }
#endif
            release_all();
        }

        SlabAllocator(const SlabAllocator&) = delete;
        SlabAllocator& operator=(const SlabAllocator&) = delete;
        SlabAllocator(SlabAllocator&&) = delete;
        SlabAllocator& operator=(SlabAllocator&&) = delete;

        template<typename... Args>
        T* allocate(Args&&... args) {
            if ((m_slabs == nullptr || m_slabs->free_list == nullptr) && m_cached_empty) {
                move_slab_to_head(m_cached_empty);
            }
            if (!m_slabs || !m_slabs->free_list) {
                add_slab();
            }

            Slab* slab = m_slabs;
            if (slab == m_cached_empty) {
                m_cached_empty = nullptr;
            }

            assert(slab->free_list && "Slab should have free slots available");
            FreeNode* node = slab->free_list;
            slab->free_list = node->next;
            slab->free_cnt--;

            m_live_objects++;
            m_peak_objects = std::max(m_peak_objects, m_live_objects);

            return std::construct_at(reinterpret_cast<T*>(node), std::forward<Args>(args)...);
        }

        void deallocate(T* obj) noexcept {
            if (!obj) {
                return;
            }
#ifdef ARENAZ_DEBUG
            assert(owns(obj) && "Pointer does not belong to this allocator");
#endif
            std::destroy_at(obj);
            Slab* slab = find_slab(obj);
            auto* node = reinterpret_cast<FreeNode*>(obj);
#ifdef ARENAZ_DEBUG
            std::fill_n(reinterpret_cast<unsigned char*>(node), Slab::slot_size(), 0xDD);
#endif
            node->next = slab->free_list;
            slab->free_list = node;
            slab->free_cnt++;

            assert(m_live_objects > 0);
            m_live_objects--;
            if (slab->free_cnt == ObjectsPerSlab) {
                if (m_cached_empty == nullptr) {
                    move_slab_to_head(slab);
                    m_cached_empty = slab;
                } else if (slab != m_cached_empty) {
                    remove_and_free_slab(slab);
                }
            }
        }

        template<typename... Args>
        std::vector<T*> allocate_bulk(size_t n, Args&&... args) {
            std::vector<T*> result;
            result.reserve(n);
            for (size_t i = 0; i < n; ++i) {
                result.push_back(allocate(std::forward<Args>(args)...));
            }

            return result;
        }

        template<typename... Args>
        void allocate_bulk_into(T** out, size_t n, Args&&... args) {
            for (size_t i = 0; i < n; ++i) {
                out[i] = allocate(std::forward<Args>(args)...);
            }
        }

        void deallocate_bulk(T** ptrs, size_t n) noexcept {
            for (size_t i = 0; i < n; ++i) {
                deallocate(ptrs[i]);
            }
        }

        void deallocate_bulk(const std::vector<T*>& vec) noexcept {
            for (T* ptr: vec) {
                deallocate(ptr);
            }
        }

        Stats stats() const noexcept {
            return {m_total_slabs, m_active_slabs, m_live_objects, m_peak_objects};
        }

        void clear() noexcept { release_all(); }

#ifdef ARENAZ_DEBUG
        bool owns(const T* obj) const noexcept { return find_slab(obj) != nullptr; }
#endif

    private:
        void add_slab() {
            auto* mem = ::operator new(sizeof(Slab), std::align_val_t(alignof(Slab)));
            Slab* slab = static_cast<Slab*>(mem);

            slab->free_cnt = ObjectsPerSlab;
            slab->free_list = nullptr;
            for (size_t i = 0; i < ObjectsPerSlab; ++i) {
                auto* node = reinterpret_cast<FreeNode*>(slab->data.data() + i * Slab::slot_size());
#ifdef ARENAZ_DEBUG
                std::fill_n(reinterpret_cast<unsigned char*>(node), Slab::slot_size(), 0xCD);
#endif
                node->next = slab->free_list;
                slab->free_list = node;
            }

            slab->next = m_slabs;
            m_slabs = slab;
            if (!m_cached_empty) {
                m_cached_empty = slab;
            }

            m_total_slabs++;
            m_active_slabs++;
        }

        void remove_and_free_slab(Slab* slab) noexcept {
            if (m_cached_empty == slab) {
                m_cached_empty = nullptr;
            }
            if (m_slabs == slab) {
                m_slabs = slab->next;
            } else {
                Slab* prev = m_slabs;
                while (prev && prev->next != slab) {
                    prev = prev->next;
                }
                if (prev) {
                    prev->next = slab->next;
                }
            }
#ifdef ARENAZ_DEBUG
            std::memset(slab, 0xDD, sizeof(Slab));
#endif
            ::operator delete(slab, std::align_val_t(alignof(Slab)));
            assert(m_active_slabs > 0);
            m_active_slabs--;
        }

        void move_slab_to_head(Slab* slab) noexcept {
            if (!slab || m_slabs == slab) {
                return;
            }
            if (m_slabs) {
                Slab* prev = m_slabs;
                if (prev == slab) {
                    return;
                }
                while (prev && prev->next != slab) {
                    prev = prev->next;
                }
                if (prev) {
                    prev->next = slab->next;
                }
            }

            slab->next = m_slabs;
            m_slabs = slab;
        }

        Slab* find_slab(const T* obj) noexcept {
            for (Slab* slab = m_slabs; slab; slab = slab->next) {
                auto* begin = slab->data.data();
                auto* end = begin + slab->data.size();
                auto* ptr = reinterpret_cast<const std::byte*>(obj);
                if (ptr >= begin && ptr < end) {
                    return slab;
                }
            }
            return nullptr;
        }

        void release_all() noexcept {
            while (m_slabs) {
                Slab* next = m_slabs->next;
#ifdef ARENAZ_DEBUG
                std::memset(m_slabs, 0xDD, sizeof(Slab));
#endif
                ::operator delete(m_slabs, std::align_val_t(alignof(Slab)));
                m_slabs = next;
                assert(m_active_slabs > 0);
                m_active_slabs--;
            }

            m_cached_empty = nullptr;
            m_live_objects = 0;
        }
    };
}  // namespace arenaz
