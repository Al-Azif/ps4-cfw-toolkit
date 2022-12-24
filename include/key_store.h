#ifndef KEY_STORE_H_
#define KEY_STORE_H_

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

#include "nlohmann/json.hpp"

extern nlohmann::json g_KeyStore;

// Allow for overloaded macros: https://stackoverflow.com/a/16683147
#define CAT(A, B) A##B
#define SELECT(NAME, NUM) CAT(NAME##_, NUM)
#define GET_COUNT(_1, _2, _3, _4, _5, _6 /* ad nauseam */, COUNT, ...) COUNT
#define VA_SIZE(...) GET_COUNT(__VA_ARGS__, 6, 5, 4, 3, 2, 1)
#define VA_SELECT(NAME, ...)         \
  SELECT(NAME, VA_SIZE(__VA_ARGS__)) \
  (__VA_ARGS__)

// Overloaded key helper macros
#define GetKey(...) VA_SELECT(GetKey, __VA_ARGS__)
#define GetKey_2(category, key) &GetKeyData(category, key)[0]
#define GetKey_3(category, key, key_index) &GetKeyData(category, key, key_index)[0]

#define GetKeyToVariable(...) VA_SELECT(GetKeyToVariable, __VA_ARGS__)
#define GetKeyToVariable_3(category, key, variable)  \
  unsigned char variable[GetKeySize(category, key)]; \
  std::memcpy(variable, GetKey_2(category, key), sizeof(variable));
#define GetKeyToVariable_4(category, key, key_index, variable)  \
  unsigned char variable[GetKeySize(category, key, key_index)]; \
  std::memcpy(variable, GetKey_3(category, key, key_index), sizeof(variable));

bool InitializeKeyStore(const std::string &p_Path);
size_t GetKeySize(const std::string &p_KeyCategory, const std::string &p_KeyName);
size_t GetKeySize(const std::string &p_KeyCategory, const std::string &p_KeyName, uint64_t p_KeyIndex);
size_t GetKeySize(const std::string &p_KeyCategory, const std::string &p_KeyName, const std::string &p_KeyIndex);
std::vector<unsigned char> GetKeyData(const std::string &p_KeyCategory, const std::string &p_KeyName);
std::vector<unsigned char> GetKeyData(const std::string &p_KeyCategory, const std::string &p_KeyName, uint64_t p_KeyIndex);
std::vector<unsigned char> GetKeyData(const std::string &p_KeyCategory, const std::string &p_KeyName, const std::string &p_KeyIndex);

#endif
