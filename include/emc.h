#ifndef EMC_H_
#define EMC_H_

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include <openssl/sha.h>

namespace emc {
typedef struct {
  unsigned char magic[0x4];
  uint16_t version;
  uint16_t type;
  uint32_t header_size;
  uint32_t body_size;
  uint32_t entry_point;
  uint32_t base_address;
  unsigned char fill_pattern[0x10];
  unsigned char key_seed[0x8];
  unsigned char body_aes_key[0x10];
  unsigned char body_hmac_key[0x10];
  unsigned char body_hmac[SHA_DIGEST_LENGTH];
  struct {
    uint64_t : 64;
  }; // 0x8 Padding
  unsigned char header_hmac[SHA_DIGEST_LENGTH];
} EmcIplHeader;

// This isn't used but it used as a shortcut for it's size
typedef struct {
  unsigned char body_aes_key[0x10];
  unsigned char body_hmac_key[0x10];
  unsigned char body_hmac[SHA_DIGEST_LENGTH];
  struct {
    uint64_t : 64;
  }; // 0x8 Padding
  unsigned char header_hmac[SHA_DIGEST_LENGTH];
} EmcIplEncryptionHeader;

bool IsEmcIpl(const unsigned char *p_Input, size_t p_InputLen);
bool Decrypt(const unsigned char *p_Input, size_t p_InputLen, std::vector<unsigned char> &p_Output);
bool Encrypt(const unsigned char *p_Input, size_t p_InputLen, std::string p_SouthbridgeRevision, std::vector<unsigned char> &p_Output);

const char c_EmcMagic_[0x4]{'\xAA', '\xF9', '\x8F', '\xD4'};
const char c_FillPattern_[0x10]{'\xDE', '\xAD', '\xBE', '\xEF', '\xCA', '\xFE', '\xBE', '\xBE', '\xDE', '\xAF', '\xBE', '\xEF', '\xCA', '\xFE', '\xBE', '\xBE'};
const char c_KeySeed_[0x8]{'\xF1', '\xF2', '\xF3', '\xF4', '\xF5', '\xF6', '\xF7', '\xF8'};
} // namespace emc

#endif
