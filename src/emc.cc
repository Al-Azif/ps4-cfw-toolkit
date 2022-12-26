#include "emc.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <vector>

#include <glog/logging.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#include "common.h"
#include "crypto.h"
#include "key_store.h"

#include "banned.h"

namespace emc {
bool IsEmcIpl(const unsigned char *p_Input, size_t p_InputLen) {
  if (p_InputLen < sizeof(c_EmcMagic_)) {
    LOG(ERROR) << "Invalid size";
    return false;
  }

  if (!CheckMagic(p_Input, c_EmcMagic_, sizeof(c_EmcMagic_))) {
    LOG(ERROR) << "Invalid magic";
    return false;
  }

  if (p_InputLen <= sizeof(EmcIplHeader)) {
    LOG(ERROR) << "Invalid size";
    return false;
  }

  EmcIplHeader *s_Header{reinterpret_cast<EmcIplHeader *>(const_cast<unsigned char *>(p_Input))};

  if (p_InputLen != sizeof(EmcIplHeader) + s_Header->body_size) {
    LOG(ERROR) << "Invalid size";
    return false;
  }

  return true;
}

bool Decrypt(const unsigned char *p_Input, size_t p_InputLen, std::vector<unsigned char> &p_Output) {
  if (p_Input == &p_Output[0]) {
    LOG(ERROR) << "Input is at the same location as output";
    return false;
  }

  p_Output.clear();
  p_Output.shrink_to_fit();

  if (p_Input == nullptr) {
    LOG(ERROR) << "Input data is NULL";
    return false;
  }
  if (p_InputLen == 0) {
    LOG(ERROR) << "Input length is zero";
    return false;
  }

  if (!IsEmcIpl(p_Input, p_InputLen)) {
    LOG(ERROR) << "File is not EMC IPL";
    return false;
  }

  EmcIplHeader *s_Header{reinterpret_cast<EmcIplHeader *>(const_cast<unsigned char *>(p_Input))};

  VLOG(1) << "s_Header->version:\n" << HexDump(&s_Header->version, sizeof(s_Header->version));
  VLOG(1) << "s_Header->type:\n" << HexDump(&s_Header->type, sizeof(s_Header->type));
  VLOG(1) << "s_Header->header_size:\n" << HexDump(&s_Header->header_size, sizeof(s_Header->header_size));
  VLOG(1) << "s_Header->body_size:\n" << HexDump(&s_Header->body_size, sizeof(s_Header->body_size));
  VLOG(1) << "s_Header->entry_point:\n" << HexDump(&s_Header->entry_point, sizeof(s_Header->entry_point));
  VLOG(1) << "s_Header->base_address:\n" << HexDump(&s_Header->base_address, sizeof(s_Header->base_address));
  VLOG(1) << "s_Header->fill_pattern:\n" << HexDump(&s_Header->fill_pattern, sizeof(s_Header->fill_pattern));
  VLOG(1) << "s_Header->key_seed:\n" << HexDump(&s_Header->key_seed, sizeof(s_Header->key_seed));

  // TODO: Determine if the correct keyset can be deduced without brute forcing
  std::vector<std::string> s_SouthbridgeRevisions{"AEOLIA", "BELIZE", "BELIZE 2", "BAIKAL"};
  for (const std::string &l_Revision : s_SouthbridgeRevisions) {
    // Create copy of s_Header to use in loop
    EmcIplHeader l_Header = *s_Header;

    VLOG(1) << "Testing keys for " << l_Revision;

    GetKeyToVariable("EMC", "IPL_AES_KEY", l_Revision, s_AesKey);
    GetKeyToVariable("EMC", "IPL_IV", l_Revision, s_Iv);
    GetKeyToVariable("EMC", "IPL_MAC_KEY", l_Revision, s_MacKey);

    VLOG(3) << "EMC_IPL_AES_KEY:\n" << HexDump(s_AesKey, sizeof(s_AesKey));
    VLOG(3) << "EMC_IPL_IV:\n" << HexDump(s_Iv, sizeof(s_Iv));
    VLOG(3) << "EMC_IPL_MAC_KEY:\n" << HexDump(s_MacKey, sizeof(s_MacKey));

    std::vector<unsigned char> s_EncryptionHeader;
    if (AesDecryptCbc(s_AesKey, sizeof(s_AesKey), s_Iv, reinterpret_cast<unsigned char *>(s_Header) + sizeof(EmcIplHeader) - sizeof(EmcIplEncryptionHeader), sizeof(EmcIplEncryptionHeader), s_EncryptionHeader) != sizeof(EmcIplEncryptionHeader)) {
      LOG(ERROR) << "Error decrypting data with " << l_Revision << " keyset";
      continue;
    }
    std::copy(s_EncryptionHeader.begin(), s_EncryptionHeader.end(), reinterpret_cast<unsigned char *>(&l_Header) + sizeof(EmcIplHeader) - s_EncryptionHeader.size());

    VLOG(1) << "s_Header->body_aes_key:\n" << HexDump(&l_Header.body_aes_key, sizeof(l_Header.body_aes_key));
    VLOG(1) << "s_Header->body_hmac_key:\n" << HexDump(&l_Header.body_hmac_key, sizeof(l_Header.body_hmac_key));
    VLOG(1) << "s_Header->body_hmac:\n" << HexDump(&l_Header.body_hmac, sizeof(l_Header.body_hmac));
    VLOG(1) << "s_Header->header_hmac:\n" << HexDump(&l_Header.header_hmac, sizeof(l_Header.header_hmac));

    std::vector<unsigned char> s_HeaderHmacReal;
    if (!HmacSha1(s_MacKey, sizeof(s_MacKey), reinterpret_cast<unsigned char *>(&l_Header), sizeof(EmcIplHeader) - sizeof(l_Header.header_hmac), s_HeaderHmacReal)) {
      LOG(WARNING) << "Error calculating header HMAC digest with " << l_Revision << " keyset";
      continue;
    }
    VLOG(2) << "s_HeaderHmacReal:\n" << HexDump(&s_HeaderHmacReal[0], s_HeaderHmacReal.size());

    if (std::memcmp(l_Header.header_hmac, &s_HeaderHmacReal[0], sizeof(l_Header.header_hmac)) != 0) {
      LOG(WARNING) << "Header HMAC does not match with " << l_Revision << " keyset";
      continue;
    }

    if (AesDecryptCbc(l_Header.body_aes_key, sizeof(l_Header.body_aes_key), s_Iv, p_Input + sizeof(EmcIplHeader), l_Header.body_size, p_Output) != l_Header.body_size) {
      LOG(ERROR) << "Error decrypting data with " << l_Revision << " keyset";
      p_Output.clear();
      p_Output.shrink_to_fit();
      continue;
    }

    std::vector<unsigned char> s_BodyHmacReal;
    if (!HmacSha1(l_Header.body_hmac_key, sizeof(l_Header.body_hmac_key), p_Input + sizeof(EmcIplHeader), l_Header.body_size, s_BodyHmacReal)) {
      LOG(WARNING) << "Error calculating body HMAC digest with " << l_Revision << " keyset";
      continue;
    }
    VLOG(2) << "s_BodyHmacReal:\n" << HexDump(&s_BodyHmacReal[0], s_BodyHmacReal.size());

    if (std::memcmp(l_Header.body_hmac, &s_BodyHmacReal[0], sizeof(l_Header.body_hmac)) != 0) {
      LOG(WARNING) << "Body HMAC does not match with " << l_Revision << " keyset";
      continue;
    }

    LOG(INFO) << "Southbridge keyset is " << l_Revision;
    return true;
  }

  LOG(ERROR) << "Could not find correct Southbridge keyset";
  return false;
}

bool Encrypt(const unsigned char *p_Input, size_t p_InputLen, std::string p_SouthbridgeRevision, std::vector<unsigned char> &p_Output) {
  if (p_Input == &p_Output[0]) {
    LOG(ERROR) << "Input is at the same location as output";
    return false;
  }

  p_Output.clear();
  p_Output.shrink_to_fit();

  if (p_Input == nullptr) {
    LOG(ERROR) << "Input data is NULL";
    return false;
  }
  if (p_InputLen == 0 || p_InputLen > 0x5FF94) { // Max size is 0x60000, packing adds an additional 0x6C bytes
    LOG(ERROR) << "Input length is invalid";
    return false;
  }
  if (p_SouthbridgeRevision != "AEOLIA" && p_SouthbridgeRevision != "BELIZE" && p_SouthbridgeRevision != "BELIZE 2" && p_SouthbridgeRevision != "BAIKAL") {
    LOG(ERROR) << "Invalid southbridge revision";
    return false;
  }

  // TODO: Check to see if input is a EMC IPL (No file magic number?)

  unsigned char s_BodyKey[AES_BLOCK_SIZE]; // Flawfinder: ignore
  if (!RAND_bytes(s_BodyKey, AES_BLOCK_SIZE)) {
    LOG(ERROR) << "Unable to generate new body AES key";
    return false;
  }

  unsigned char s_BodyIv[AES_BLOCK_SIZE]; // Flawfinder: ignore
  std::memset(s_BodyIv, '\0', AES_BLOCK_SIZE);

  unsigned char s_BodyHmacKey[AES_BLOCK_SIZE]; // Flawfinder: ignore
  if (!RAND_bytes(s_BodyHmacKey, AES_BLOCK_SIZE)) {
    LOG(ERROR) << "Unable to generate new body MAC key";
    return false;
  }

  std::vector<unsigned char> s_EncryptedBody;
  if (AesEncryptCbc(s_BodyKey, AES_BLOCK_SIZE, s_BodyIv, p_Input, p_InputLen, s_EncryptedBody) != p_InputLen) {
    LOG(ERROR) << "Error decrypting data";
    return false;
  }

  std::vector<unsigned char> s_BodyHmac;
  if (!HmacSha1(s_BodyHmacKey, AES_BLOCK_SIZE, &s_EncryptedBody[0], s_EncryptedBody.size(), s_BodyHmac)) {
    LOG(ERROR) << "Error calculating body HMAC digest";
    return false;
  }

  EmcIplHeader s_Header;
  std::copy(c_EmcMagic_, c_EmcMagic_ + sizeof(s_Header.magic), s_Header.magic);
  s_Header.version = 1;
  s_Header.type = 0x4801;                                 // TODO: Is this calculated by version/item, or static
  s_Header.entry_point = 1051648;                         // TODO: Is this calculated by version/item, or static
  s_Header.base_address = 1051648;                        // TODO: Is this calculated by version/item, or static
  s_Header.body_size = static_cast<uint32_t>(p_InputLen); // An oversized size_t is indirectly checked for earlier in this function
  s_Header.header_size = sizeof(EmcIplHeader);
  std::copy(c_FillPattern_, c_FillPattern_ + sizeof(s_Header.fill_pattern), s_Header.fill_pattern); // TODO: Is this calculated by version/item, or static
  std::copy(c_KeySeed_, c_KeySeed_ + sizeof(s_Header.key_seed), s_Header.key_seed);                 // TODO: Is this calculated by version/item, or static

  std::copy(s_BodyKey, s_BodyKey + sizeof(s_Header.body_aes_key), s_Header.body_aes_key);
  std::copy(s_BodyHmacKey, s_BodyHmacKey + sizeof(s_Header.body_hmac_key), s_Header.body_hmac_key);
  std::copy(s_BodyHmac.begin(), s_BodyHmac.begin() + sizeof(s_Header.body_hmac), s_Header.body_hmac);

  GetKeyToVariable("EMC", "IPL_AES_KEY", p_SouthbridgeRevision, s_AesKey);
  GetKeyToVariable("EMC", "IPL_IV", p_SouthbridgeRevision, s_Iv);
  GetKeyToVariable("EMC", "IPL_MAC_KEY", p_SouthbridgeRevision, s_MacKey);

  VLOG(3) << "EMC_IPL_AES_KEY:\n" << HexDump(s_AesKey, sizeof(s_AesKey));
  VLOG(3) << "EMC_IPL_IV:\n" << HexDump(s_Iv, sizeof(s_Iv));
  VLOG(3) << "EMC_IPL_MAC_KEY:\n" << HexDump(s_MacKey, sizeof(s_MacKey));

  std::vector<unsigned char> s_HeaderHmac;
  if (!HmacSha1(s_MacKey, sizeof(s_MacKey), reinterpret_cast<unsigned char *>(&s_Header), sizeof(EmcIplHeader) - sizeof(s_Header.header_hmac), s_HeaderHmac)) {
    LOG(ERROR) << "Error calculating header HMAC digest with " << p_SouthbridgeRevision << " keyset";
    return false;
  }

  std::copy(s_HeaderHmac.begin(), s_HeaderHmac.begin() + sizeof(s_Header.header_hmac), s_Header.header_hmac);

  VLOG(1) << "s_Header->version:\n" << HexDump(&s_Header.version, sizeof(s_Header.version));
  VLOG(1) << "s_Header->type:\n" << HexDump(&s_Header.type, sizeof(s_Header.type));
  VLOG(1) << "s_Header->header_size:\n" << HexDump(&s_Header.header_size, sizeof(s_Header.header_size));
  VLOG(1) << "s_Header->body_size:\n" << HexDump(&s_Header.body_size, sizeof(s_Header.body_size));
  VLOG(1) << "s_Header->entry_point:\n" << HexDump(&s_Header.entry_point, sizeof(s_Header.entry_point));
  VLOG(1) << "s_Header->base_address:\n" << HexDump(&s_Header.base_address, sizeof(s_Header.base_address));
  VLOG(1) << "s_Header->fill_pattern:\n" << HexDump(&s_Header.fill_pattern, sizeof(s_Header.fill_pattern));
  VLOG(1) << "s_Header->key_seed:\n" << HexDump(&s_Header.key_seed, sizeof(s_Header.key_seed));
  VLOG(1) << "s_Header->body_aes_key:\n" << HexDump(&s_Header.body_aes_key, sizeof(s_Header.body_aes_key));
  VLOG(1) << "s_Header->body_hmac_key:\n" << HexDump(&s_Header.body_hmac_key, sizeof(s_Header.body_hmac_key));
  VLOG(1) << "s_Header->body_hmac:\n" << HexDump(&s_Header.body_hmac, sizeof(s_Header.body_hmac));
  VLOG(1) << "s_Header->header_hmac:\n" << HexDump(&s_Header.header_hmac, sizeof(s_Header.header_hmac));

  std::vector<unsigned char> s_EncryptedHeader;
  if (AesEncryptCbc(s_AesKey, sizeof(s_AesKey), s_Iv, reinterpret_cast<unsigned char *>(&s_Header) + sizeof(EmcIplHeader) - sizeof(EmcIplEncryptionHeader), sizeof(EmcIplEncryptionHeader), s_EncryptedHeader) != sizeof(EmcIplEncryptionHeader)) {
    LOG(ERROR) << "Error encrypting data";
    return false;
  }
  std::copy(s_EncryptedHeader.begin(), s_EncryptedHeader.end(), reinterpret_cast<unsigned char *>(&s_Header) + sizeof(EmcIplHeader) - s_EncryptedHeader.size());

  p_Output.insert(p_Output.end(), reinterpret_cast<unsigned char *>(&s_Header), reinterpret_cast<unsigned char *>(&s_Header) + sizeof(s_Header));
  p_Output.insert(p_Output.end(), s_EncryptedBody.begin(), s_EncryptedBody.end());

  return true;
}
} // namespace emc
