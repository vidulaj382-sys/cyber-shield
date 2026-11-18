#pragma once
// Unit III: class template. Owns heap-allocated objects (Unit I: dynamic memory).
#include <cstddef>
#include <vector>
#include "Exceptions.h"

namespace cyber {

template <typename T>
class Repository {
public:
    Repository() = default;
    ~Repository() { clear(); }

    // Owning raw pointers: copying would double-delete, so forbid it.
    Repository(const Repository&) = delete;
    Repository& operator=(const Repository&) = delete;

    void add(T* item) {
        if (item == nullptr)
            throw ValidationException("cannot add a null item");
        items.push_back(item);
    }

    Repository& operator+=(T* item) {
        add(item);
        return *this;
    }

    T* operator[](std::size_t index) const {
        if (index >= items.size())
            throw NotFoundException("index " + std::to_string(index));
        return items[index];
    }

    T* findById(int id) const {
        for (T* item : items)
            if (item->getId() == id)
                return item;
        return nullptr;
    }

    template <typename Pred>
    T* findIf(Pred pred) const {
        for (T* item : items)
            if (pred(*item))
                return item;
        return nullptr;
    }

    bool remove(int id) {
        for (auto it = items.begin(); it != items.end(); ++it) {
            if ((*it)->getId() == id) {
                delete *it;
                items.erase(it);
                return true;
            }
        }
        return false;
    }

    void clear() {
        for (T* item : items)
            delete item;
        items.clear();
    }

    std::size_t size() const { return items.size(); }
    bool empty() const { return items.empty(); }

    typename std::vector<T*>::const_iterator begin() const { return items.begin(); }
    typename std::vector<T*>::const_iterator end() const { return items.end(); }

private:
    std::vector<T*> items;
};

} // namespace cyber
