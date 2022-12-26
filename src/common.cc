#include "common.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <ios>
#include <sstream>
#include <string>
#include <vector>

#include <glog/logging.h>

#include "banned.h"

bool CheckMagic(const unsigned char *p_Input, const char *p_Magic, size_t p_MagicLen) {
  if (p_Input == nullptr) {
    LOG(ERROR) << "Input data is NULL";
    return false;
  }
  if (p_Magic == nullptr) {
    LOG(ERROR) << "Input magic is NULL";
    return false;
  }
  if (p_MagicLen == 0) {
    LOG(ERROR) << "Magic length is zero";
    return false;
  }

  // TODO: This does not work because one of the Magics we use has a null terminator in it which breaks strnlen
  // if (strnlen(reinterpret_cast<const char *>(const_cast<unsigned char *>(p_Input)), p_MagicLen) < p_MagicLen || strnlen(p_Magic, p_MagicLen) < p_MagicLen) {
  //   LOG(ERROR) << "Magic length is too large";
  //   return false;
  // }

  if (std::memcmp(p_Input, p_Magic, p_MagicLen) != 0) {
    LOG(ERROR) << "Magic does not match";
    return false;
  }

  return true;
}

// Checks if string is empty
bool IsEmptyString(const std::string &p_InputString) {
  if (p_InputString.empty() || std::all_of(p_InputString.begin(), p_InputString.end(), [](char c) { return std::isspace(c); })) {
    return true;
  }

  return false;
}

bool WriteFile(const unsigned char *p_Input, size_t p_InputLen, const std::string &p_OutputPath, int64_t p_Offset) {
  if (p_Input == nullptr && p_InputLen != 0) {
    LOG(ERROR) << "Input data is NULL";
    return false;
  }

  if (IsEmptyString(p_OutputPath)) {
    LOG(ERROR) << "Empty path argument";
    return false;
  }

  // Zero byte files DO exist, but we can use this check to help find/debug issues
  if (p_InputLen == 0) {
    LOG(WARNING) << "Input length is zero";
  }

  // mkdir -p
  std::filesystem::path s_RootDirectory(p_OutputPath);
  s_RootDirectory.remove_filename();
  if (!IsEmptyString(s_RootDirectory.string())) {
    if (!std::filesystem::exists(s_RootDirectory)) {
      if (!std::filesystem::create_directories(s_RootDirectory)) {
        LOG(ERROR) << "Failed to create directory: " << s_RootDirectory;
        return false;
      }
    }
  }

  // Exists, but is not a file
  if (std::filesystem::exists(p_OutputPath) && !std::filesystem::is_regular_file(p_OutputPath)) {
    LOG(ERROR) << "Output path exists, but is not a file: " << p_OutputPath;
    return false;
  }

  // Write
  if (p_Offset == 0) {
    std::ofstream s_OutputFile(p_OutputPath, std::ios::out | std::ios::trunc | std::ios::binary);
    if (!s_OutputFile || !s_OutputFile.good()) {
      LOG(ERROR) << "Cannot open output file: " << p_OutputPath;
      s_OutputFile.close();
      return false;
    }

    s_OutputFile.write(reinterpret_cast<char *>(const_cast<unsigned char *>(&p_Input[0])), p_InputLen);
    s_OutputFile.close();
  } else {
    std::ofstream s_OutputFile(p_OutputPath, std::ios::out | std::ios::in | std::ios::binary);
    if (!s_OutputFile || !s_OutputFile.good()) {
      LOG(ERROR) << "Cannot open output file: " << p_OutputPath;
      s_OutputFile.close();
      return false;
    }

    s_OutputFile.seekp(p_Offset, std::ios::beg);
    s_OutputFile.write(reinterpret_cast<char *>(const_cast<unsigned char *>(&p_Input[0])), p_InputLen);
    s_OutputFile.close();
  }

  return true;
}

bool EndsWith(const std::string &p_Input, const std::string &p_Match) {
  if (IsEmptyString(p_Match) && !IsEmptyString(p_Input)) {
    return false;
  }

  if (p_Input.size() >= p_Match.size() && p_Input.compare(p_Input.size() - p_Match.size(), p_Match.size(), p_Match) == 0) {
    return true;
  }

  return false;
}

// Hexdump based on: https://stackoverflow.com/a/29865
std::string HexDump(const void *p_Pointer, uint32_t p_Len) {
  const unsigned char *s_Buffer{static_cast<const unsigned char *>(p_Pointer)};

  std::stringstream s_OutputString;

  for (uint32_t i{0}; i < p_Len; i += 16) {
    s_OutputString << std::uppercase << std::setfill('0') << std::setw(8) << std::hex << i << ": ";
    for (uint32_t j{0}; j < 16; j++) {
      if (i + j < p_Len) {
        s_OutputString << std::uppercase << std::setfill('0') << std::setw(2) << std::hex << static_cast<uint32_t>(s_Buffer[i + j]) << " ";
      } else {
        s_OutputString << "   ";
      }
      if (j == 7) {
        s_OutputString << " ";
      }
    }

    s_OutputString << " ";

    for (uint32_t j{0}; j < 16; j++) {
      if (i + j < p_Len) {
        if (isprint(s_Buffer[i + j])) {
          s_OutputString << s_Buffer[i + j];
        } else {
          s_OutputString << ".";
        }
      }
    }

    if (i + 16 < p_Len) {
      s_OutputString << "\n";
    }
  }

  return s_OutputString.str();
}
