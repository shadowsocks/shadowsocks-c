/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef SS_CORE_INTRUSIVE_LIST_HPP
#define SS_CORE_INTRUSIVE_LIST_HPP

// IntrusiveList<T, Tag>: a doubly linked list whose links live inside the
// elements. Replaces ss_list (core.h).
//
// An element type derives from ListNode<Tag> once per list it can be on.
// The list never owns its elements; it only links objects whose lifetime
// is managed elsewhere (usually a pool). Destroying a linked node unlinks
// it, so an element can never leave a dangling link behind.
//
// Owner recovery uses static_cast from the base class, which is well
// defined, instead of ss_container_of pointer arithmetic.

#include <cstddef>
#include <cstdlib>

namespace ss {

struct DefaultListTag;

template <class Tag = DefaultListTag>
class ListNode {
public:
    ListNode() noexcept = default;
    ListNode(const ListNode &)            = delete;
    ListNode &operator=(const ListNode &) = delete;
    ~ListNode() { unlink(); }

    bool linked() const noexcept { return next_ != nullptr; }

    void unlink() noexcept
    {
        if (next_ != nullptr) {
            prev_->next_ = next_;
            next_->prev_ = prev_;
            next_ = prev_ = nullptr;
        }
    }

private:
    template <class, class>
    friend class IntrusiveList;

    ListNode *prev_ = nullptr;
    ListNode *next_ = nullptr;
};

template <class T, class Tag = DefaultListTag>
class IntrusiveList {
    using Node = ListNode<Tag>;

public:
    IntrusiveList() noexcept { head_.prev_ = head_.next_ = &head_; }
    IntrusiveList(const IntrusiveList &)            = delete;
    IntrusiveList &operator=(const IntrusiveList &) = delete;
    ~IntrusiveList() { clear(); }

    bool empty() const noexcept { return head_.next_ == &head_; }

    std::size_t size() const noexcept
    {
        std::size_t n = 0;
        for (const Node *p = head_.next_; p != &head_; p = p->next_) {
            ++n;
        }
        return n;
    }

    void push_back(T &item) noexcept { insert_before(&head_, node(item)); }
    void push_front(T &item) noexcept { insert_before(head_.next_, node(item)); }

    // Move an element that is already on this list to the back.
    void move_to_back(T &item) noexcept
    {
        Node *n = node(item);
        n->unlink();
        insert_before(&head_, n);
    }

    static void remove(T &item) noexcept { node(item)->unlink(); }

    T *front() noexcept { return empty() ? nullptr : owner(head_.next_); }
    T *back() noexcept { return empty() ? nullptr : owner(head_.prev_); }

    // The element after `item` (which must be on this list), or null.
    T *next(T &item) noexcept
    {
        Node *n = node(item)->next_;
        return n == &head_ ? nullptr : owner(n);
    }

    T *pop_front() noexcept
    {
        T *item = front();
        if (item != nullptr) {
            remove(*item);
        }
        return item;
    }

    // Unlink everything without touching the elements' lifetimes.
    void clear() noexcept
    {
        while (!empty()) {
            head_.next_->unlink();
        }
    }

    // Visit every element. The callback may unlink or destroy the element
    // it was given (the next pointer is read first), but not others.
    template <class F>
    void for_each(F &&f)
    {
        Node *p = head_.next_;
        while (p != &head_) {
            Node *next = p->next_;
            f(*owner(p));
            p = next;
        }
    }

    // The first element `pred` accepts, or null.
    template <class P>
    T *find_if(P &&pred)
    {
        for (Node *p = head_.next_; p != &head_; p = p->next_) {
            if (pred(*owner(p))) {
                return owner(p);
            }
        }
        return nullptr;
    }

private:
    static Node *node(T &item) noexcept { return static_cast<Node *>(&item); }
    static T *owner(Node *n) noexcept { return static_cast<T *>(n); }

    static void insert_before(Node *pos, Node *n) noexcept
    {
        if (n->linked()) {
            std::abort(); // already on a list using this tag
        }
        n->next_     = pos;
        n->prev_     = pos->prev_;
        pos->prev_->next_ = n;
        pos->prev_   = n;
    }

    Node head_;
};

} // namespace ss

#endif
