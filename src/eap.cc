#include "eap.h"

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

namespace eap {
bool IsEapKbl(const unsigned char *p_Input, size_t p_InputLen) {
  if (p_InputLen < sizeof(c_EapKblMagic_)) {
    LOG(ERROR) << "Invalid size";
    return false;
  }

  if (!CheckMagic(p_Input, c_EapKblMagic_, sizeof(c_EapKblMagic_))) {
    LOG(ERROR) << "Invalid magic";
    return false;
  }

  if (p_InputLen < sizeof(EapKblHeader)) {
    LOG(ERROR) << "Invalid size";
    return false;
  }

  EapKblHeader *s_Header{reinterpret_cast<EapKblHeader *>(const_cast<unsigned char *>(p_Input))};

  if (p_InputLen != sizeof(EapKblHeader) + s_Header->body_size) {
    LOG(ERROR) << "Invalid size";
    return false;
  }

  return true;
}

bool IsEapKernel(const unsigned char *p_Input, size_t p_InputLen) {
  if (p_InputLen < sizeof(c_EapKernelMagic_)) {
    LOG(ERROR) << "Invalid size";
    return false;
  }

  if (!CheckMagic(p_Input, c_EapKernelMagic_, sizeof(c_EapKernelMagic_))) {
    LOG(ERROR) << "Invalid magic";
    return false;
  }

  if (p_InputLen < sizeof(EapKernelHeader)) {
    LOG(ERROR) << "Invalid size";
    return false;
  }

  EapKernelHeader *s_StorageHeader{reinterpret_cast<EapKernelHeader *>(const_cast<unsigned char *>(p_Input))};

  if (s_StorageHeader->version != c_ExpectedVersion_) {
    LOG(ERROR) << "Invalid version";
    return false;
  }

  // Can't calculate total size without decrypting first, so we'll end this here as it's out of scope of the function

  return true;
}

bool DecryptKbl(const unsigned char *p_Input, size_t p_InputLen, std::vector<unsigned char> &p_Output) {
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
  if (p_InputLen <= 0) {
    LOG(ERROR) << "Input length is zero";
    return false;
  }

  if (!IsEapKbl(p_Input, p_InputLen)) {
    LOG(ERROR) << "File is not EAP KBL";
    return false;
  }

  EapKblHeader *s_Header{reinterpret_cast<EapKblHeader *>(const_cast<unsigned char *>(p_Input))};

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
    EapKblHeader l_Header = *s_Header;

    VLOG(1) << "Testing keys for " << l_Revision;

    GetKeyToVariable("EAP", "KBL_AES_KEY", l_Revision, s_AesKey);
    GetKeyToVariable("EAP", "KBL_IV", l_Revision, s_Iv);
    GetKeyToVariable("EAP", "KBL_MAC_KEY", l_Revision, s_MacKey);

    VLOG(3) << "EAP_KBL_AES_KEY:\n" << HexDump(s_AesKey, sizeof(s_AesKey));
    VLOG(3) << "EAP_KBL_IV:\n" << HexDump(s_Iv, sizeof(s_Iv));
    VLOG(3) << "EAP_KBL_MAC_KEY:\n" << HexDump(s_MacKey, sizeof(s_MacKey));

    std::vector<unsigned char> s_EncryptionHeader;
    if (AesDecryptCbc(s_AesKey, sizeof(s_AesKey), s_Iv, reinterpret_cast<unsigned char *>(s_Header) + sizeof(EapKblHeader) - sizeof(EapKblEncryptionHeader), sizeof(EapKblEncryptionHeader), s_EncryptionHeader) != sizeof(EapKblEncryptionHeader)) {
      LOG(ERROR) << "Error decrypting data with " << l_Revision << " keyset";
      continue;
    }
    std::copy(s_EncryptionHeader.begin(), s_EncryptionHeader.end(), reinterpret_cast<unsigned char *>(&l_Header) + sizeof(EapKblHeader) - s_EncryptionHeader.size());

    VLOG(1) << "s_Header->body_aes_key:\n" << HexDump(&l_Header.body_aes_key, sizeof(l_Header.body_aes_key));
    VLOG(1) << "s_Header->body_hmac_key:\n" << HexDump(&l_Header.body_hmac_key, sizeof(l_Header.body_hmac_key));
    VLOG(1) << "s_Header->body_hmac:\n" << HexDump(&l_Header.body_hmac, sizeof(l_Header.body_hmac));
    VLOG(1) << "s_Header->header_hmac:\n" << HexDump(&l_Header.header_hmac, sizeof(l_Header.header_hmac));

    std::vector<unsigned char> s_HeaderHmacReal;
    if (!HmacSha1(s_MacKey, sizeof(s_MacKey), reinterpret_cast<unsigned char *>(&l_Header), sizeof(EapKblHeader) - sizeof(l_Header.header_hmac), s_HeaderHmacReal)) {
      LOG(WARNING) << "Error calculating header HMAC digest with " << l_Revision << " keyset";
      continue;
    }
    VLOG(2) << "s_HeaderHmacReal:\n" << HexDump(&s_HeaderHmacReal[0], s_HeaderHmacReal.size());

    if (std::memcmp(l_Header.header_hmac, &s_HeaderHmacReal[0], sizeof(l_Header.header_hmac)) != 0) {
      LOG(WARNING) << "Header HMAC does not match with " << l_Revision << " keyset";
      continue;
    }

    if (AesDecryptCbc(l_Header.body_aes_key, sizeof(l_Header.body_aes_key), s_Iv, p_Input + sizeof(EapKblHeader), l_Header.body_size, p_Output) != l_Header.body_size) {
      LOG(ERROR) << "Error decrypting data with " << l_Revision << " keyset";
      p_Output.clear();
      p_Output.shrink_to_fit();
      continue;
    }

    std::vector<unsigned char> s_BodyHmacReal;
    if (!HmacSha1(l_Header.body_hmac_key, sizeof(l_Header.body_hmac_key), p_Input + sizeof(EapKblHeader), l_Header.body_size, s_BodyHmacReal)) {
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

bool DecryptKernel(const unsigned char *p_Input, size_t p_InputLen, std::vector<unsigned char> &p_Output) {
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
  if (p_InputLen <= 0) {
    LOG(ERROR) << "Input length is zero";
    return false;
  }

  if (!IsEapKernel(p_Input, p_InputLen)) {
    LOG(ERROR) << "File is not EAP kernel";
    return false;
  }

  EapKernelHeader *s_StorageHeader{reinterpret_cast<EapKernelHeader *>(const_cast<unsigned char *>(p_Input))};

  VLOG(1) << "s_StorageHeader->storage_version:\n" << HexDump(&s_StorageHeader->version, sizeof(s_StorageHeader->version));
  VLOG(1) << "s_StorageHeader->storage_iv:\n" << HexDump(&s_StorageHeader->iv, sizeof(s_StorageHeader->iv));
  VLOG(1) << "s_StorageHeader->storage_digest:\n" << HexDump(&s_StorageHeader->digest, sizeof(s_StorageHeader->digest));

  // TODO: Determine if the correct keyset can be deduced without brute forcing
  // 0 = Proto, 1 = 1.00, 2 = Old, 3 = New
  for (uint8_t i{0}; i <= 3; i++) {
    std::vector<unsigned char> s_Storage;

    GetKeyToVariable("EAP", "KERNEL_ENC_KEY", i, s_EncKey);
    GetKeyToVariable("EAP", "KERNEL_MAC_KEY", i, s_MacKey);

    VLOG(3) << "EAP_KERNEL_ENC_KEY:\n" << HexDump(s_EncKey, sizeof(s_EncKey));
    VLOG(3) << "EAP_KERNEL_MAC_KEY:\n" << HexDump(s_MacKey, sizeof(s_MacKey));

    constexpr size_t s_EncStorageSize{c_SectorSize_ - sizeof(EapKernelHeader)};

    if (AesDecryptCbcCts(s_EncKey, sizeof(s_EncKey), s_StorageHeader->iv, p_Input + sizeof(EapKernelHeader), s_EncStorageSize, s_Storage) != s_EncStorageSize) {
      LOG(WARNING) << "Error decrypting data with keyset #" << static_cast<unsigned int>(i) << ", attempting next keyset";
      continue;
    }

    std::vector<unsigned char> s_StorageDigestReal;
    if (!HmacSha1(s_MacKey, sizeof(s_MacKey), &s_Storage[0], s_Storage.size(), s_StorageDigestReal)) {
      LOG(WARNING) << "Error calculating storage digest with keyset #" << static_cast<unsigned int>(i) << ", attempting next keyset";
      continue;
    }
    VLOG(2) << "s_StorageDigestReal:\n" << HexDump(&s_StorageDigestReal[0], s_StorageDigestReal.size());

    if (std::memcmp(s_StorageHeader->digest, &s_StorageDigestReal[0], sizeof(s_StorageHeader->digest)) != 0) {
      LOG(WARNING) << "Invalid storage header digest with keyset #" << static_cast<unsigned int>(i) << ", attempting next keyset";
      continue;
    }

    EapKernelBodyInfo *s_BodyInfoHeader{reinterpret_cast<EapKernelBodyInfo *>(const_cast<unsigned char *>(&s_Storage[0]))};
    if (!CheckMagic(s_BodyInfoHeader->magic, c_EapBodyInfoHeaderMagic_, sizeof(c_EapBodyInfoHeaderMagic_))) {
      LOG(ERROR) << "Invalid magic";
      continue;
    }
    VLOG(1) << "s_BodyInfoHeader->size: " << static_cast<unsigned int>(s_BodyInfoHeader->size);
    VLOG(1) << "s_BodyInfoHeader->offset: " << hex(s_BodyInfoHeader->offset);

    EapKernelHeader *s_BodyHeader{reinterpret_cast<EapKernelHeader *>(const_cast<unsigned char *>(p_Input + s_BodyInfoHeader->offset))};

    if (!CheckMagic(s_BodyHeader->magic, c_EapBodyHeaderMagic_, sizeof(c_EapBodyHeaderMagic_))) {
      LOG(ERROR) << "Invalid magic";
      continue;
    }

    if (s_BodyHeader->version != c_ExpectedVersion_) {
      LOG(ERROR) << "Invalid version";
      continue;
    }

    VLOG(1) << "s_BodyHeader->version:\n" << HexDump(&s_BodyHeader->version, sizeof(s_BodyHeader->version));
    VLOG(1) << "s_BodyHeader->iv:\n" << HexDump(&s_BodyHeader->iv, sizeof(s_BodyHeader->iv));
    VLOG(1) << "s_BodyHeader->digest:\n" << HexDump(&s_BodyHeader->digest, sizeof(s_BodyHeader->digest));

    if (AesDecryptCbcCts(s_EncKey, sizeof(s_EncKey), s_BodyHeader->iv, p_Input + s_BodyInfoHeader->offset + sizeof(EapKernelHeader), s_BodyInfoHeader->size - sizeof(EapKernelHeader), p_Output) != s_BodyInfoHeader->size - sizeof(EapKernelHeader)) {
      LOG(ERROR) << "Error decrypting data";
      p_Output.clear();
      p_Output.shrink_to_fit();
      continue;
    }

    std::vector<unsigned char> s_BodyDigestReal;
    if (!HmacSha1(s_MacKey, sizeof(s_MacKey), &p_Output[0], p_Output.size(), s_BodyDigestReal)) {
      LOG(WARNING) << "Error calculating body digest";
      continue;
    }
    VLOG(2) << "s_BodyDigestReal:\n" << HexDump(&s_BodyDigestReal[0], s_BodyDigestReal.size());

    if (std::memcmp(s_BodyHeader->digest, &s_BodyDigestReal[0], sizeof(s_BodyHeader->digest)) != 0) {
      LOG(WARNING) << "Invalid body header digest";
      continue;
    }

    LOG(INFO) << "EAP kernel uses keyset #" << static_cast<unsigned int>(i);
    return true;
  }

  LOG(ERROR) << "Could not find correct EAP kernel keyset";
  return false;
}

bool EncryptKbl(const unsigned char *p_Input, size_t p_InputLen, std::string p_SouthbridgeRevision, std::vector<unsigned char> &p_Output) {
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
  if (p_InputLen <= 0 || p_InputLen > UINT32_MAX) { // TODO: Check for ACTUAL valid max length
    LOG(ERROR) << "Input length is invalid";
    return false;
  }
  if (p_SouthbridgeRevision != "AEOLIA" && p_SouthbridgeRevision != "BELIZE" && p_SouthbridgeRevision != "BELIZE 2" && p_SouthbridgeRevision != "BAIKAL") {
    LOG(ERROR) << "Invalid southbridge revision";
    return false;
  }

  if (!CheckMagic(p_Input, c_EapElfMagic_, sizeof(c_EapElfMagic_))) {
    LOG(ERROR) << "Invalid magic";
    return false;
  }

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

  EapKblHeader s_Header;
  std::copy(c_EapKblMagic_, c_EapKblMagic_ + sizeof(s_Header.magic), s_Header.magic);
  s_Header.version = 1;
  s_Header.type = 0x6801;                                 // TODO: Is this calculated by version/item, or static
  s_Header.entry_point = 1677721600;                      // TODO: Is this calculated by version/item, or static
  s_Header.base_address = 1677721600;                     // TODO: Is this calculated by version/item, or static
  s_Header.body_size = static_cast<uint32_t>(p_InputLen); // Oversized size_t are tested against `UINT32_MAX` above
  s_Header.header_size = sizeof(EapKblHeader);
  std::copy(c_FillPattern_, c_FillPattern_ + sizeof(s_Header.fill_pattern), s_Header.fill_pattern); // TODO: Is this calculated by version/item, or static
  std::copy(c_KeySeed_, c_KeySeed_ + sizeof(s_Header.key_seed), s_Header.key_seed);                 // TODO: Is this calculated by version/item, or static

  std::copy(s_BodyKey, s_BodyKey + sizeof(s_Header.body_aes_key), s_Header.body_aes_key);
  std::copy(s_BodyHmacKey, s_BodyHmacKey + sizeof(s_Header.body_hmac_key), s_Header.body_hmac_key);
  std::copy(s_BodyHmac.begin(), s_BodyHmac.begin() + sizeof(s_Header.body_hmac), s_Header.body_hmac);

  GetKeyToVariable("EAP", "KBL_AES_KEY", p_SouthbridgeRevision, s_AesKey);
  GetKeyToVariable("EAP", "KBL_IV", p_SouthbridgeRevision, s_Iv);
  GetKeyToVariable("EAP", "KBL_MAC_KEY", p_SouthbridgeRevision, s_MacKey);

  VLOG(3) << "EAP_IPL_AES_KEY:\n" << HexDump(s_AesKey, sizeof(s_AesKey));
  VLOG(3) << "EAP_IPL_IV:\n" << HexDump(s_Iv, sizeof(s_Iv));
  VLOG(3) << "EAP_KBL_MAC_KEY:\n" << HexDump(s_MacKey, sizeof(s_MacKey));

  std::vector<unsigned char> s_HeaderHmac;
  if (!HmacSha1(s_MacKey, sizeof(s_MacKey), reinterpret_cast<unsigned char *>(&s_Header), sizeof(EapKblHeader) - sizeof(s_Header.header_hmac), s_HeaderHmac)) {
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
  AesEncryptCbc(s_AesKey, sizeof(s_AesKey), s_Iv, reinterpret_cast<unsigned char *>(&s_Header) + sizeof(EapKblHeader) - sizeof(EapKblEncryptionHeader), sizeof(EapKblEncryptionHeader), s_EncryptedHeader);
  std::copy(s_EncryptedHeader.begin(), s_EncryptedHeader.end(), reinterpret_cast<unsigned char *>(&s_Header) + sizeof(EapKblHeader) - s_EncryptedHeader.size());

  p_Output.insert(p_Output.end(), reinterpret_cast<unsigned char *>(&s_Header), reinterpret_cast<unsigned char *>(&s_Header) + sizeof(s_Header));
  p_Output.insert(p_Output.end(), s_EncryptedBody.begin(), s_EncryptedBody.end());

  return true;
}

bool EncryptKernel(const unsigned char *p_Input, size_t p_InputLen, uint32_t p_KeysetNumber, std::vector<unsigned char> &p_Output) {
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
  if (p_InputLen <= 0 || p_InputLen > UINT32_MAX) { // TODO: Check for ACTUAL valid max length
    LOG(ERROR) << "Input length is invalid";
    return false;
  }
  if (p_KeysetNumber < 0 || p_KeysetNumber > 3) {
    LOG(ERROR) << "Invalid keyset selection";
    return false;
  }

  if (!CheckMagic(p_Input, c_EapElfMagic_, sizeof(c_EapElfMagic_))) {
    LOG(ERROR) << "Invalid magic";
    return false;
  }

  EapKernelHeader s_BodyHeader;
  std::copy(c_EapBodyHeaderMagic_, c_EapBodyHeaderMagic_ + sizeof(s_BodyHeader.magic), s_BodyHeader.magic);
  s_BodyHeader.version = c_ExpectedVersion_;

  if (!RAND_bytes(s_BodyHeader.iv, AES_BLOCK_SIZE)) {
    LOG(ERROR) << "Unable to generate new body AES key";
    return false;
  }

  GetKeyToVariable("EAP", "KERNEL_ENC_KEY", p_KeysetNumber, s_EncKey);
  GetKeyToVariable("EAP", "KERNEL_MAC_KEY", p_KeysetNumber, s_MacKey);

  VLOG(3) << "EAP_KERNEL_MAC_KEY:\n" << HexDump(s_MacKey, sizeof(s_MacKey));
  VLOG(3) << "EAP_KERNEL_ENC_KEY:\n" << HexDump(s_EncKey, sizeof(s_EncKey));

  std::vector<unsigned char> s_BodyHmac;
  if (!HmacSha1(s_MacKey, sizeof(s_MacKey), p_Input, p_InputLen, s_BodyHmac)) {
    LOG(WARNING) << "Error calculating body digest";
    return false;
  }
  std::copy(s_BodyHmac.begin(), s_BodyHmac.begin() + sizeof(s_BodyHeader.digest), s_BodyHeader.digest);
  VLOG(1) << "s_BodyHeader.digest:\n" << HexDump(s_BodyHeader.digest, sizeof(s_BodyHeader.digest));

  std::vector<unsigned char> s_Body;
  if (AesEncryptCbcCts(s_EncKey, sizeof(s_EncKey), s_BodyHeader.iv, p_Input, p_InputLen, s_Body) != p_InputLen) {
    LOG(ERROR) << "Error Encrypting data";
    return false;
  }

  EapKernelBodyInfo s_BodyInfoHeader;
  std::copy(c_EapBodyInfoHeaderMagic_, c_EapBodyInfoHeaderMagic_ + sizeof(s_BodyInfoHeader.magic), s_BodyInfoHeader.magic);
  s_BodyInfoHeader.size = s_Body.size() + sizeof(EapKernelHeader);
  s_BodyInfoHeader.offset = c_SectorSize_;

  VLOG(1) << "s_BodyInfoHeader.size: " << static_cast<unsigned int>(s_BodyInfoHeader.size);
  VLOG(1) << "s_BodyInfoHeader.offset: " << hex(s_BodyInfoHeader.offset);

  constexpr size_t s_StorageSize{c_SectorSize_ - sizeof(EapKernelHeader)};
  std::vector<unsigned char> s_Storage(s_StorageSize, '\0');
  std::copy(s_Storage.begin(), s_Storage.begin() + sizeof(s_BodyInfoHeader), reinterpret_cast<unsigned char *>(&s_BodyInfoHeader));

  std::vector<unsigned char> s_EncStorage;
  if (AesEncryptCbcCts(s_EncKey, sizeof(s_EncKey), s_BodyHeader.iv, &s_Storage[0], s_StorageSize, s_EncStorage) != s_StorageSize) {
    LOG(ERROR) << "Error Encrypting data";
    return false;
  }

  EapKernelHeader s_StorageHeader;
  std::copy(c_EapKernelMagic_, c_EapKernelMagic_ + sizeof(s_StorageHeader.magic), s_StorageHeader.magic);
  s_StorageHeader.version = c_ExpectedVersion_;
  std::copy(s_BodyHeader.iv, s_BodyHeader.iv + sizeof(s_StorageHeader.iv), s_StorageHeader.iv);
  std::vector<unsigned char> s_StorageHmac;
  if (!HmacSha1(s_MacKey, sizeof(s_MacKey), &s_Storage[0], s_Storage.size(), s_StorageHmac)) {
    LOG(WARNING) << "Error calculating storage digest";
    return false;
  }
  std::copy(s_StorageHmac.begin(), s_StorageHmac.begin() + sizeof(s_StorageHeader.digest), s_StorageHeader.digest);
  VLOG(1) << "s_StorageHeader.digest:\n" << HexDump(s_StorageHeader.digest, sizeof(s_StorageHeader.digest));

  p_Output.insert(p_Output.begin(), reinterpret_cast<unsigned char *>(&s_StorageHeader), reinterpret_cast<unsigned char *>(&s_StorageHeader) + sizeof(s_StorageHeader));
  p_Output.insert(p_Output.end(), s_EncStorage.begin(), s_EncStorage.end());
  p_Output.insert(p_Output.end(), reinterpret_cast<unsigned char *>(&s_BodyHeader), reinterpret_cast<unsigned char *>(&s_BodyHeader) + sizeof(s_BodyHeader));
  p_Output.insert(p_Output.end(), s_Body.begin(), s_Body.end());

  // TODO: Zero pad? Or is the padding I see an unrelated issue in the test file (BLS extraction)

  return true;
}
} // namespace eap
