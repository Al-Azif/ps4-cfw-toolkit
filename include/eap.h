#ifndef EAP_H_
#define EAP_H_

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include <openssl/sha.h>

namespace eap {
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
} EapKblHeader;

// This isn't used but it used as a shortcut for it's size, make sure it
// matches the body onward of the struct above it
typedef struct {
  unsigned char body_aes_key[0x10];
  unsigned char body_hmac_key[0x10];
  unsigned char body_hmac[SHA_DIGEST_LENGTH];
  struct {
    uint64_t : 64;
  }; // 0x8 Padding
  unsigned char header_hmac[SHA_DIGEST_LENGTH];
} EapKblEncryptionHeader;

typedef struct {
  unsigned char magic[0x4];
  uint32_t version;
  unsigned char iv[0x10];
  unsigned char digest[SHA_DIGEST_LENGTH];
} EapKernelHeader;

typedef struct {
  unsigned char magic[0x4];
  uint32_t size;
  uint32_t offset;
} EapKernelBodyInfo;

bool IsEapKbl(const unsigned char *p_Input, size_t p_InputLen);
bool IsEapKernel(const unsigned char *p_Input, size_t p_InputLen);
bool DecryptKbl(const unsigned char *p_Input, size_t p_InputLen, std::vector<unsigned char> &p_Output);
bool DecryptKernel(const unsigned char *p_Input, size_t p_InputLen, std::vector<unsigned char> &p_Output);
bool EncryptKbl(const unsigned char *p_Input, size_t p_InputLen, std::string p_SouthbridgeRevision, std::vector<unsigned char> &p_Output);
bool EncryptKernel(const unsigned char *p_Input, size_t p_InputLen, uint32_t p_KeysetNumber, std::vector<unsigned char> &p_Output);

const char c_EapElfMagic_[0x4]{'\x7F', '\x45', '\x4C', '\x46'};

const char c_EapKblMagic_[0x4]{'\xAA', '\xF9', '\x8F', '\xD4'};
const char c_EapKernelMagic_[0x4]{'\x5C', '\xC9', '\xEB', '\x12'};
const char c_EapBodyInfoHeaderMagic_[0x4]{'\x00', '\x6E', '\x72', '\x4B'};
const char c_EapBodyHeaderMagic_[0x4]{'\x5C', '\xC9', '\xEB', '\x12'};

const char c_FillPattern_[0x10]{'\xDE', '\xAD', '\xBE', '\xEF', '\xCA', '\xFE', '\xBE', '\xBE', '\xDE', '\xAF', '\xBE', '\xEF', '\xCA', '\xFE', '\xBE', '\xBE'};
const char c_KeySeed_[0x8]{'\xF1', '\xF2', '\xF3', '\xF4', '\xF5', '\xF6', '\xF7', '\xF8'};

const uint32_t c_ExpectedVersion_{0x10000};
const uint16_t c_SectorSize_{0x200};
} // namespace eap

#endif
