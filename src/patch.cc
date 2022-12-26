#include "patch.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

#include <glog/logging.h>

#include "common.h"

#include "banned.h"

namespace patch {
bool Offset(unsigned char *p_Input, size_t p_InputLen, const char *p_Patch, size_t p_PatchLen, size_t p_Offset) {
  if (p_InputLen < p_PatchLen + p_Offset) {
    LOG(ERROR) << "Patch must not overflow input";
    return false;
  }

  std::copy(p_Patch, p_Patch + p_PatchLen, p_Input + p_Offset);

  return true;
}

uint64_t Pattern(unsigned char *p_Input, size_t p_InputLen, const char *p_Search, size_t p_SearchLen, const char *p_Replace, size_t p_ReplaceLen, size_t p_Occurances) {
  if (p_InputLen == 0 || p_SearchLen == 0 || p_ReplaceLen == 0) {
    return 0;
  }
  if (p_InputLen < p_ReplaceLen) {
    LOG(ERROR) << "Patch must not overflow input";
    return 0;
  }

  size_t s_Limit{std::max(p_SearchLen, p_ReplaceLen)};
  size_t s_HitCount{0};
  for (size_t i{0}; i < p_InputLen - s_Limit; i++) {
    if (p_Occurances != 0 && s_HitCount >= p_Occurances) {
      break;
    }
    if (p_Input[i] == p_Search[0]) {
      if (std::memcmp(&p_Input[i], p_Search, p_SearchLen) == 0) {
        VLOG(1) << "Found match for patching at: " << hex(i);
        Offset(p_Input, p_InputLen, p_Replace, p_ReplaceLen, i);
        s_HitCount++;

        // Skip what we just patched so we don't go locked here
        i += p_SearchLen;
      }
    }
  }

  return s_HitCount;
}

uint64_t PatternStartAt(unsigned char *p_Input, size_t p_InputLen, const char *p_Search, size_t p_SearchLen, const char *p_Replace, size_t p_ReplaceLen, size_t p_StartAddr, size_t p_Occurances) {
  if (p_InputLen == 0 || p_SearchLen == 0 || p_ReplaceLen == 0 || p_InputLen == p_StartAddr) {
    return 0;
  }
  if (p_InputLen < p_StartAddr) {
    LOG(ERROR) << "Patch must not overflow input";
    return 0;
  }

  return Pattern(p_Input + p_StartAddr, p_InputLen - p_StartAddr, p_Search, p_SearchLen, p_Replace, p_ReplaceLen, p_Occurances);
}

uint64_t PatternEndAt(unsigned char *p_Input, size_t p_InputLen, const char *p_Search, size_t p_SearchLen, const char *p_Replace, size_t p_ReplaceLen, size_t p_EndAddr, size_t p_Occurances) {
  if (p_InputLen == 0 || p_SearchLen == 0 || p_ReplaceLen == 0) {
    return 0;
  }
  if (p_InputLen < p_EndAddr) {
    LOG(ERROR) << "Patch must not overflow input";
    return 0;
  }

  return Pattern(p_Input, p_EndAddr, p_Search, p_SearchLen, p_Replace, p_ReplaceLen, p_Occurances);
}

uint64_t PatternBetween(unsigned char *p_Input, size_t p_InputLen, const char *p_Search, size_t p_SearchLen, const char *p_Replace, size_t p_ReplaceLen, size_t p_StartAddr, size_t p_EndAddr, size_t p_Occurances) {
  if (p_InputLen == 0 || p_SearchLen == 0 || p_ReplaceLen == 0) {
    return 0;
  }
  if (p_EndAddr < p_StartAddr) {
    LOG(ERROR) << "Patch end address is before start address";
    return 0;
  }
  if (p_InputLen < p_StartAddr) {
    LOG(ERROR) << "Patch must not overflow input";
    return 0;
  }
  size_t s_EndAddr{p_EndAddr};
  if (p_InputLen < p_EndAddr) {
    LOG(WARNING) << "Patch must not overflow input, using end of ipnut as end address";
    s_EndAddr = p_InputLen;
  }

  return Pattern(p_Input + p_StartAddr, s_EndAddr - p_StartAddr, p_Search, p_SearchLen, p_Replace, p_ReplaceLen, p_Occurances);
}
} // namespace patch
