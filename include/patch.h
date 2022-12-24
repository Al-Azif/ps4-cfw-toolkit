#ifndef PATCH_H_
#define PATCH_H_

#include <cstddef>
#include <cstdint>

namespace patch {
bool Offset(unsigned char *p_Input, size_t p_InputLen, const char *p_Patch, size_t p_PatchLen, size_t p_Offset);
uint64_t Pattern(unsigned char *p_Input, size_t p_InputLen, const char *p_Search, size_t p_SearchLen, const char *p_Replace, size_t p_ReplaceLen, size_t p_Occurances = 0);
uint64_t PatternStartAt(unsigned char *p_Input, size_t p_InputLen, const char *p_Search, size_t p_SearchLen, const char *p_Replace, size_t p_ReplaceLen, size_t p_StartAddr, size_t p_Occurances = 0);
uint64_t PatternEndAt(unsigned char *p_Input, size_t p_InputLen, const char *p_Search, size_t p_SearchLen, const char *p_Replace, size_t p_ReplaceLen, size_t p_EndAddr, size_t p_Occurances = 0);
uint64_t PatternBetween(unsigned char *p_Input, size_t p_InputLen, const char *p_Search, size_t p_SearchLen, const char *p_Replace, size_t p_ReplaceLen, size_t p_StartAddr, size_t p_EndAddr, size_t p_Occurances = 0);
} // namespace patch

#endif
