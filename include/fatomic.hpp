#ifndef FATOMIC_HPP
#define FATOMIC_HPP

#include <atomic>

template <typename T> class fatomic : public std::atomic<T> {
public:
  fatomic(T value) { this->store(value); }
  operator T() const { return this->load(); }

  bool operator<(const T &other) const { return this->load() < other; }
  bool operator>(const T &other) const { return this->load() > other; }
};
#endif
