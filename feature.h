// Copyright 2022 The Centipede Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// This library defines the conctepts "fuzzing feature" and "feature domain".
// It is used by Centipede, and it can be used by fuzz runners to
// define their features in a way most friendly to Centipede.
// Fuzz runners do not have to use this file nor to obey the rules defened here.
// But using this file and following its rules is the simplest way if you want
// Centipede to understand the details about the features generated by the
// runner.
//
// This library must not depend on anything other than libc so that fuzz targets
// using it don't gain redundant coverage. For the same reason this library
// uses raw __builtin_trap instead of CHECKs.
// We make an exception for <algorithm> for std::sort/std::unique,
// since <algorithm> is very lightweight.
// This library is also header-only, with all functions defined as inline.

#ifndef THIRD_PARTY_CENTIPEDE_FEATURE_H_
#define THIRD_PARTY_CENTIPEDE_FEATURE_H_

#include <stddef.h>
#include <string.h>

// WARNING!!!: Be very careful with what STL headers or other dependencies you
// add here. This header needs to remain mostly bare-bones so that we can
// include it into runner.
// <vector> is an exception, because it's too clumsy w/o it, and it introduces
// minimal code footprint.
#include <cstdint>
#include <memory>
#include <vector>

namespace centipede {

// Feature is an integer that identifies some unique behaviour
// of the fuzz target exercised by a given input.
// We say, this input has this feature with regard to this fuzz target.
// One example of a feature: a certain control flow edge being executed.
using feature_t = uint64_t;

// A vector of features. It is not expected to be ordered.
// It typically does not contain repetitions, but it's ok to have them.
using FeatureVec = std::vector<feature_t>;

namespace FeatureDomains {

// Feature domain is a subset of 64-bit integers dedicated to a certain
// kind of fuzzing features.
// All domains are of the same size (kSize), the first domain starts with zero,
// the second is adjacent to the first and so on.
// This way, we can compute a domain for a given feature by dividing by kSize.
struct Domain {
  enum DomainId {
    kUnknown = 0,
    k8bitCounters,
    kDataFlow,
    kCMP,
    kBoundedPath,
    kPCPair,
    kLastDomain,  // Should remain the last.
  };
  static constexpr size_t kSize = 1ULL << 40;

  DomainId domain_id;

  constexpr feature_t begin() const { return kSize * domain_id; }
  constexpr feature_t end() const { return begin() + kSize; }
  bool Contains(feature_t feature) const {
    return feature >= begin() && feature < end();
  }

  // Converts any `number` into a feature in this domain.
  feature_t ConvertToMe(size_t number) const {
    return begin() + number % kSize;
  }

  // Returns the DomainId of the domain that the feature belongs to, or
  // LastDomain if the feature is outside of all domains.
  static DomainId FeatureToDomainId(feature_t feature) {
    size_t idx = feature / kSize;
    if (idx >= kLastDomain) return kLastDomain;
    return static_cast<DomainId>(idx);
  }
};

// The first 2^32 features are reserved as unknown, just in case.
// Fuzz runners that don't obey the rules in this file will likely utilize
// features from this domain.
constexpr Domain kUnknown = {Domain::kUnknown};

// Features derived from
// https://clang.llvm.org/docs/SanitizerCoverage.html#inline-8bit-counters.
// Every such feature corresponds to one control flow edge and its counter,
// see Convert8bitCounterToFeature and Convert8bitCounterFeatureToPcIndex.
constexpr Domain k8bitCounters = {Domain::k8bitCounters};

// Features derived from data flow edges.
// A typical data flow edge is a pair of PCs: {store-PC, load-PC}.
// Another variant of a data flow edge is a pair of {global-address, load-PC}.
constexpr Domain kDataFlow = {Domain::kDataFlow};

// Features derived from instrumenting CMP instructions.
constexpr Domain kCMP = {Domain::kCMP};

// Features derived from computing (bounded) control flow paths.
// Even bounded paths can be very numerous, so we intentionally limit
// their number to 2^32.
constexpr Domain kBoundedPath = {Domain::kBoundedPath};

// Features derived from (unordered) pairs of PCs.
constexpr Domain kPCPair = {Domain::kPCPair};

// Don't put any domains after this one.
constexpr Domain kLastDomain = {Domain::kLastDomain};

// Returns a number in range [1,1000) indicating how important `feature` is.
// 1 is the least important.
// The result can be used for computing weights of feature vectors.
uint32_t Importance(feature_t feature);

}  // namespace FeatureDomains

// Converts a 8-bit coverage counter,  i.e. a pair of
// {`pc_index`, `counter_value`} into a number.
// `counter_value` must not be zero.
//
// We convert the 8-bit counter value to a number from 0 to 7
// by computing its binary log, i.e. 1=>0, 2=>1, 4=>2, 8=>3, ..., 128=>7.
// This is a heuristic, similar to that of AFL or libFuzzer
// that tries to encourage inputs with different number of repetitions
// of the same PC.
inline size_t Convert8bitCounterToNumber(size_t pc_index,
                                         uint8_t counter_value) {
  if (counter_value == 0) __builtin_trap();  // Wrong input.
  // Compute a log2 of counter_value, i.e. a value between 0 and 7.
  // __builtin_clz consumes a 32-bit integer.
  uint32_t counter_log2 =
      sizeof(uint32_t) * 8 - 1 - __builtin_clz(counter_value);
  return pc_index * 8 + counter_log2;
}

// Iterates over [bytes, bytes + num_bytes) and calls action(idx, bytes[idx]),
// for every non-zero bytes[idx].
// Optimized for the case where lots of bytes are zero.
template <typename Action>
inline void ForEachNonZeroByte(const uint8_t *bytes, size_t num_bytes,
                               Action action) {
  // The main loop will read words of this size.
  const uintptr_t kWordSize = sizeof(uintptr_t);
  uintptr_t initial_alignment = reinterpret_cast<uintptr_t>(bytes) % kWordSize;
  size_t idx = 0;
  uintptr_t alignment = initial_alignment;
  // Iterate the first few until we reach alignment by word size.
  for (; idx < num_bytes && alignment != 0;
       idx++, alignment = (alignment + 1) % kWordSize) {
    if (bytes[idx]) action(idx, bytes[idx]);
  }
  // Iterate one word at a time. If the word is != 0, iterate its bytes.
  for (; idx + kWordSize - 1 < num_bytes; idx += kWordSize) {
    uintptr_t wide_load;
    memcpy(&wide_load, bytes + idx, kWordSize);
    if (!wide_load) continue;
    // This loop assumes little-endiannes. (Tests will break on big-endian).
    for (size_t pos = 0; pos < kWordSize; pos++) {
      uint8_t value = wide_load >> (pos * 8);  // lowest byte is taken.
      if (value) action(idx + pos, value);
    }
  }
  // Iterate the last few.
  for (; idx < num_bytes; idx++) {
    if (bytes[idx]) action(idx, bytes[idx]);
  }
}

// Given the `feature` from the k8bitCounters domain, returns the feature's
// pc_index. I.e. reverse of Convert8bitCounterToFeature.
inline size_t Convert8bitCounterFeatureToPcIndex(feature_t feature) {
  auto domain = FeatureDomains::k8bitCounters;
  if (!domain.Contains(feature)) __builtin_trap();
  return (feature - domain.begin()) / 8;
}

// Encodes {`pc1`, `pc2`} into a number.
// `pc1` and `pc2` are in range [0, `max_pc`)
inline size_t ConvertPcPairToNumber(uintptr_t pc1, uintptr_t pc2,
                                    uintptr_t max_pc) {
  return pc1 * max_pc + pc2;
}

// Encodes {pc, a, b} into a number.
// a and b are arguments of an instruction "a CMP b" at pc.
// pc is less than max_pc.
//
// This function has several mutually conflicting requirements:
//  * it must be very fast, as it is executed on every CMP instruction.
//  * it must allow to distinguish {a,b} pairs in some non-trivial way.
//  * it must not produce too many different values
//    (where "too many" is hard to define)
inline size_t ConvertPcAndArgPairToNumber(uintptr_t a, uintptr_t b,
                                          uintptr_t pc, uintptr_t max_pc) {
  // Below is a giant unscientific heuristic.
  // Expect quite a bit of tuning effort here.
  //
  // The idea is to treat different {pc,a,b} tuples as different features,
  // so that a sufficiently new argument pair for a given pc is recognized
  // as interesting.
  // Obviously, we can't generate max_pc*2^128 different features
  // and so we need to bucketize them.
  //
  // The following relationships between a and b seem worthy of
  // differentiation via different feature values:
  //  * a==b
  //  * [diff]      a==b+K or a==b-K (for some small K, e.g. 1 to 31).
  //  * [hamming]   Different values of hamming distance.
  //  * [msb_eq]    The number of most significant bits being equal.
  //  * [diff_log2] Different values of Log2(a-b)
  // We compute a superposition of these properties.
  //
  // Similar ideas:
  // * https://lafintel.wordpress.com/
  // * https://llvm.org/docs/LibFuzzer.html#value-profile

  // ab is the component of the feature based on {a,b}.
  uintptr_t ab = 0;  // Value for the case of a == b;
  if (a != b) {
    uintptr_t diff = a - b;
    // diff_component is in [0,64)
    uintptr_t diff_component = diff < 32 ? diff : -diff < 32 ? 32 + -diff : 0;
    // hamming_component is in [0, 64)
    uintptr_t hamming_component = __builtin_popcountll(a ^ b) - 1;
    // diff_log2_component is in [0, 64)
    uintptr_t diff_log2_component = __builtin_clzll(diff);
    // msb_eq_component is in [0, 64)
    uintptr_t msb_eq_component = __builtin_clzll(a ^ b);
    ab = (diff_component << 0) | (hamming_component << 6) |
         (diff_log2_component << 12) | (msb_eq_component << 18);
    // This gives us whooping 2^24 different features for just one PC.
    // In theory this is pretty bad: it will bloat the corpus beyond reasonable.
    // Whether it's bad in practice remains to be seen.
    // We may want to reduce the number of different features with e.g. this:
    // ab %= 7919;  // mod large prime
  }
  // Combine {a,b} and pc.
  return ab * max_pc + pc;
}

// Fixed-size ring buffer that maintains a hash of its `kSize` elements.
// Create objects of this type as zero-initialized globals or thread-locals.
// In a zero-initialized object all values and the hash are zero.
template <size_t kSize>
class HashedRingBuffer {
 public:
  // Adds `new_item` and returns the new hash of the entire collection.
  // Evicts an old item.
  size_t push(size_t new_item) {
    size_t new_pos = (last_added_pos_ + 1) % kSize;
    size_t evicted_item = buffer_[new_pos];
    // The items added are not necesserily random bit strings,
    // and just blindly XOR-ing them together may not work.
    // So, mix all bits in new_item by multiplying it by a large prime.
    constexpr size_t kPrimeMultiplier = 13441014529ULL;
    new_item *= kPrimeMultiplier;
    buffer_[new_pos] = new_item;
    hash_ ^= evicted_item;
    hash_ ^= new_item;
    last_added_pos_ = new_pos;
    return hash_;
  }

  // Zero-initialize the object.
  void clear() { memset(this, 0, sizeof(*this)); }

 private:
  size_t buffer_[kSize];   // All elements.
  size_t last_added_pos_;  // Position of the last added element.
  size_t hash_;            // XOR of all elements in buffer_.
};

// A fixed-size bitset with a lossy concurrent set() function.
// kSize must be a multiple of 512 - this allows the implementation
// to use any word size up to 64 bytes.
template <size_t kSizeInBits>
class ConcurrentBitSet {
 public:
  static_assert((kSizeInBits % 512) == 0);
  // Constructs an empty bit set.
  ConcurrentBitSet() { clear(); }

  // Clears the bit set.
  void clear() { memset(words_, 0, sizeof(words_)); }

  // Sets the bit `idx % kSizeInBits`.
  // set() can be called concurrently with another set().
  // If several threads race to update adjacent bits,
  // the update may be lost (i.e. set() is lossy).
  // We could use atomic set-bit instructions to make it non-lossy,
  // but it is going to be too expensive.
  void set(size_t idx) {
    idx %= kSizeInBits;
    size_t word_idx = idx / kBitsInWord;
    size_t bit_idx = idx % kBitsInWord;
    word_t mask = 1ULL << bit_idx;
    word_t word = __atomic_load_n(&words_[word_idx], __ATOMIC_RELAXED);
    if (!(word & mask)) {
      word |= mask;
      __atomic_store_n(&words_[word_idx], word, __ATOMIC_RELAXED);
    }
  }

  // Calls `action(index)` for every index of a non-zero bit in the set.
  template <typename Action>
  __attribute__((noinline)) void ForEachNonZeroBit(Action action) {
    for (size_t word_idx = 0; word_idx < kSizeInWords; word_idx++) {
      if (word_t word = words_[word_idx]) {
        do {
          size_t bit_idx = __builtin_ctzll(word);
          action(word_idx * kBitsInWord + bit_idx);
          word_t mask = 1ULL << bit_idx;
          word &= ~mask;
        } while (word);
      }
    }
  }

 private:
  using word_t = uintptr_t;
  static const size_t kBitsInWord = 8 * sizeof(word_t);
  static const size_t kSizeInWords = kSizeInBits / kBitsInWord;
  word_t words_[kSizeInWords];
};

// A simple fixed-size byte array.
// Each element is a 8-bit counter that can be incremented concurrently.
// The counters are allowed to overflow (i.e. are not saturating).
// Thread-compatible.
template <size_t kSize>
class CounterArray {
 public:
  // Constructs an empty counter array.
  CounterArray() { Clear(); }

  // Clears all counters.
  void Clear() { memset(data_, 0, sizeof(data_)); }

  // Increments the counter that corresponds to idx.
  // Idx is taken modulo kSize.
  void Increment(size_t idx) {
    // An atomic increment is quite expensive, even if relaxed.
    // We may want to do a racy non-atomic increment instead.
    __atomic_add_fetch(&data_[idx % kSize], 1, __ATOMIC_RELAXED);
  }

  // Accessors.
  const uint8_t *data() const { return &data_[0]; }
  size_t size() const { return kSize; }

 private:
  uint8_t data_[kSize];
};

// A simple fixed-capacity array with push_back.
// Thread-compatible.
template <size_t kSize>
class FeatureArray {
 public:
  // pushes `feature` back if there is enough space.
  void push_back(feature_t feature) {
    if (num_features_ < kSize) {
      features_[num_features_++] = feature;
    }
  }

  // Makes the array empty.
  void clear() { num_features_ = 0; }

  // Returns the array's raw data.
  feature_t *data() { return &features_[0]; }

  // Returns the number of elements in the array.
  size_t size() const { return num_features_; }

 private:
  feature_t features_[kSize];
  size_t num_features_ = 0;
};

}  // namespace centipede

#endif  // THIRD_PARTY_CENTIPEDE_FEATURE_H_
