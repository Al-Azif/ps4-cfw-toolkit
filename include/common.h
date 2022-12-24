#ifndef COMMON_H_
#define COMMON_H_

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <iomanip>
#include <ios>
#include <ostream>
#include <string>

#define MAX_PATH 255

#ifdef _WIN32
#define OS_SEP '\\'
#define CONST_OS_SEP "\\"
#else
#define OS_SEP '/'
#define CONST_OS_SEP "/"
#endif

template <class T>
inline std::string hex(T x) {
  std::stringstream s_HexAssembler;
  s_HexAssembler << std::uppercase << std::hex << std::setw(sizeof(T) * 2) << std::setfill('0') << static_cast<uint64_t>(x);
  std::string s_Output = s_HexAssembler.str();
  s_Output.erase(0, std::min(s_Output.find_first_not_of("00"), s_Output.size() - 2));
  return "0x" + s_Output;
}

bool CheckMagic(const unsigned char *p_Input, const char *p_Magic, size_t p_MagicLen);
bool IsEmptyString(const std::string &p_InputString);
bool WriteFile(const unsigned char *p_Input, size_t p_InputLen, const std::string &p_OutputPath, int64_t p_Offset = 0);
bool EndsWith(const std::string &p_Input, const std::string &p_Match);
std::string HexDump(const void *p_Pointer, uint32_t p_Len);

#endif
