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
    template<typename T, size_t ObjectsPerSlab = 64, size_t MaxCachedEmptySlabs = 2>
    class SlabAllocator {
    private:
        struct FreeNode {
            FreeNode* next;
        };

        struct Slab {
            static constexpr size_t slot_size =
                ((std::max(sizeof(T), sizeof(FreeNode)) + alignof(T) - 1) / alignof(T)) *
                alignof(T);

            static constexpr size_t total_bytes = ObjectsPerSlab * slot_size;

            Slab* prev{nullptr};
            Slab* next{nullptr};
            FreeNode* free_list{nullptr};
            size_t free_cnt{0};

            alignas(T) std::array<std::byte, total_bytes> data;
        };

        Slab* m_partial{nullptr};
        Slab* m_full{nullptr};
        Slab* m_empty{nullptr};

        size_t m_created_slabs{0};
        size_t m_active_slabs{0};
        size_t m_live_objects{0};
        size_t m_peak_objects{0};
        size_t m_cached_empty{0};

    public:
        struct Stats {
            size_t created_slabs;
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
            if (!m_partial) {
                if (m_empty) {
                    Slab* slab = detach(m_empty);
                    --m_cached_empty;
                    attach(m_partial, slab);
                } else {
                    Slab* slab = create_slab();
                    attach(m_partial, slab);
                }
            }

            assert(m_partial && m_partial->free_list);

            Slab* slab = m_partial;
            FreeNode* node = slab->free_list;
            slab->free_list = node->next;
            slab->free_cnt--;

            T* obj = std::construct_at(reinterpret_cast<T*>(node), std::forward<Args>(args)...);
            ++m_live_objects;
            m_peak_objects = std::max(m_peak_objects, m_live_objects);

            if (slab->free_cnt == 0) {
                detach(m_partial, slab);
                attach(m_full, slab);
            }

            return obj;
        }

        void deallocate(T* obj) noexcept {
            if (!obj) {
                return;
            }

            Slab* slab = find_slab(obj);
#ifdef ARENAZ_DEBUG
            assert(slab && "Pointer does not belong to this allocator");
#endif
            std::destroy_at(obj);

            auto* node = reinterpret_cast<FreeNode*>(obj);
#ifdef ARENAZ_DEBUG
            std::fill_n(reinterpret_cast<unsigned char*>(node), Slab::slot_size, 0xDD);
#endif
            node->next = slab->free_list;
            slab->free_list = node;
            slab->free_cnt++;

            assert(m_live_objects > 0);
            --m_live_objects;

            if (slab->free_cnt == 1) {
                detach(m_full, slab);
                attach(m_partial, slab);
            } else if (slab->free_cnt == ObjectsPerSlab) {
                detach(m_partial, slab);
                if (m_cached_empty < MaxCachedEmptySlabs) {
                    attach(m_empty, slab);
                    ++m_cached_empty;
                } else {
                    destroy_slab(slab);
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
            for (T* p: vec) {
                deallocate(p);
            }
        }

        Stats stats() const noexcept {
            return Stats{.created_slabs = m_created_slabs,
                         .active_slabs = m_active_slabs,
                         .live_objects = m_live_objects,
                         .peak_objects = m_peak_objects};
        }

        void clear() noexcept { release_all(); }

    private:
        static void attach(Slab*& list, Slab* slab) noexcept {
            slab->prev = nullptr;
            slab->next = list;
            if (list) {
                list->prev = slab;
            }

            list = slab;
        }

        static Slab* detach(Slab*& list) noexcept {
            if (!list) {
                return nullptr;
            }

            Slab* s = list;
            list = s->next;
            if (list) {
                list->prev = nullptr;
            }

            s->prev = s->next = nullptr;
            return s;
        }

        static void detach(Slab*& list, Slab* slab) noexcept {
            if (!slab) {
                return;
            }
            if (slab->prev) {
                slab->prev->next = slab->next;
            } else {
                list = slab->next;
            }

            if (slab->next) {
                slab->next->prev = slab->prev;
            }

            slab->prev = slab->next = nullptr;
        }

        Slab* create_slab() {
            void* mem = ::operator new(sizeof(Slab), std::align_val_t(alignof(Slab)));
            Slab* slab = new (mem) Slab();
            slab->free_cnt = ObjectsPerSlab;
            slab->free_list = nullptr;
            for (size_t i = 0; i < ObjectsPerSlab; ++i) {
                auto* base = slab->data.data() + i * Slab::slot_size;
                auto* node = reinterpret_cast<FreeNode*>(base);
#ifdef ARENAZ_DEBUG
                std::fill_n(reinterpret_cast<unsigned char*>(node), Slab::slot_size, 0xCD);
#endif
                node->next = slab->free_list;
                slab->free_list = node;
            }

            ++m_created_slabs;
            ++m_active_slabs;
            return slab;
        }

        void destroy_slab(Slab* slab) noexcept {
            if (!slab) {
                return;
            }
#ifdef ARENAZ_DEBUG
            std::memset(slab, 0xDD, sizeof(Slab));
#endif
            ::operator delete(slab, std::align_val_t(alignof(Slab)));
            assert(m_active_slabs > 0);
            --m_active_slabs;
        }

        void release_all() noexcept {
            auto free_list = [&](Slab*& head) {
                while (head) {
                    Slab* next = head->next;
#ifdef ARENAZ_DEBUG
                    std::memset(head, 0xDD, sizeof(Slab));
#endif
                    ::operator delete(head, std::align_val_t(alignof(Slab)));
                    head = next;
                    assert(m_active_slabs > 0);
                    --m_active_slabs;
                }
            };

            free_list(m_partial);
            free_list(m_full);
            free_list(m_empty);

            m_cached_empty = 0;
            m_live_objects = 0;
        }

        Slab* find_slab(const T* obj) noexcept {
            auto search = [&](Slab* list) -> Slab* {
                for (Slab* slab = list; slab; slab = slab->next) {
                    auto* begin = slab->data.data();
                    auto* end = begin + slab->data.size();
                    auto* ptr = reinterpret_cast<const std::byte*>(obj);
                    if (ptr >= begin && ptr < end) {
                        return slab;
                    }
                }
                return nullptr;
            };

            if (auto* s = search(m_partial)) {
                return s;
            }
            if (auto* s = search(m_full)) {
                return s;
            }
            if (auto* s = search(m_empty)) {
                return s;
            }
            return nullptr;
        }
    };
}  // namespace arenaz
