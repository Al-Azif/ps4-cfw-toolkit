#include "key_store.h"

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

#include <glog/logging.h>

#include "nlohmann/json.hpp"

nlohmann::json g_KeyStore;

bool InitializeKeyStore(const std::string &p_Path) {
  if (std::filesystem::exists(p_Path) && !std::filesystem::is_regular_file(p_Path)) {
    LOG(ERROR) << "Key store path exists, but is not a file: " << p_Path;
    return false;
  }

  std::ifstream s_InputFile(p_Path, std::ios::in);
  if (!s_InputFile || !s_InputFile.good()) {
    LOG(ERROR) << "Key store file could not be read: " << p_Path;
    s_InputFile.close();
    return false;
  }

  g_KeyStore = nlohmann::json::parse(s_InputFile);
  return true;
}

size_t GetKeySize(const std::string &p_KeyCategory, const std::string &p_KeyName) {
  std::string s_KeyString{g_KeyStore[p_KeyCategory][p_KeyName]};

  size_t s_Return{s_KeyString.size()};
  if (s_Return != 0 && s_Return % 2 != 0) {
    s_Return++;
  }
  return s_Return / 2;
}

size_t GetKeySize(const std::string &p_KeyCategory, const std::string &p_KeyName, uint64_t p_KeyIndex) {
  std::stringstream s_StringAssembler;
  s_StringAssembler << p_KeyIndex;

  return GetKeySize(p_KeyCategory, p_KeyName, s_StringAssembler.str());
}

size_t GetKeySize(const std::string &p_KeyCategory, const std::string &p_KeyName, const std::string &p_KeyIndex) {
  std::string s_KeyString{g_KeyStore[p_KeyCategory][p_KeyName][p_KeyIndex]};

  size_t s_Return{s_KeyString.size()};
  if (s_Return != 0 && s_Return % 2 != 0) {
    s_Return++;
  }
  return s_Return / 2;
}

std::vector<unsigned char> GetKeyData(const std::string &p_KeyCategory, const std::string &p_KeyName) {
  std::vector<unsigned char> s_KeyVector;

  std::string s_KeyString{g_KeyStore[p_KeyCategory][p_KeyName]};
  for (size_t i{0}; i < s_KeyString.length(); i += 2) {
    std::string sByteString{s_KeyString.substr(i, 2)};
    char s_Byte{(char)strtol(sByteString.c_str(), NULL, 16)};
    s_KeyVector.push_back(s_Byte);
  }

  return s_KeyVector;
}

std::vector<unsigned char> GetKeyData(const std::string &p_KeyCategory, const std::string &p_KeyName, uint64_t p_KeyIndex) {
  std::stringstream s_StringAssembler;
  s_StringAssembler << p_KeyIndex;

  return GetKeyData(p_KeyCategory, p_KeyName, s_StringAssembler.str());
}

std::vector<unsigned char> GetKeyData(const std::string &p_KeyCategory, const std::string &p_KeyName, const std::string &p_KeyIndex) {
  std::vector<unsigned char> s_KeyVector;

  std::string s_KeyString{g_KeyStore[p_KeyCategory][p_KeyName][p_KeyIndex]};
  for (size_t i{0}; i < s_KeyString.length(); i += 2) {
    std::string s_ByteString{s_KeyString.substr(i, 2)};
    char s_Byte{(char)strtol(s_ByteString.c_str(), NULL, 16)};
    s_KeyVector.push_back(s_Byte);
  }

  return s_KeyVector;
}
