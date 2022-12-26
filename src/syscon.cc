#include "syscon.h"

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <vector>

#include <glog/logging.h>

#include "common.h"
#include "crypto.h"
#include "key_store.h"

#include "banned.h"

namespace syscon {
static bool DecryptCommon(unsigned char *p_AesKey, size_t p_AesLen, unsigned char *p_Iv, unsigned char *p_MacKey, size_t p_MacLen, const unsigned char *p_Input, size_t p_InputLen, std::vector<unsigned char> &p_Output) {
  VLOG(3) << "AES_KEY:\n" << HexDump(p_AesKey, p_AesLen);
  VLOG(3) << "IV:\n" << HexDump(p_Iv, 0x10);
  VLOG(3) << "MAC_KEY:\n" << HexDump(p_MacKey, p_MacLen);

  p_Output.clear();
  p_Output.shrink_to_fit();

  if (AesDecryptCbc(p_AesKey, p_AesLen, p_Iv, p_Input, p_InputLen, p_Output) != p_InputLen) {
    LOG(ERROR) << "Error decrypting data";
    p_Output.clear();
    p_Output.shrink_to_fit();
    return false;
  }

  // The static value `0x10` below is the MAC length per rfc4493
  std::vector<unsigned char> s_CalculatedCmac;
  if (!Cmac(p_MacKey, p_MacLen, &p_Output[0x10], p_Output.size() - 0x10, s_CalculatedCmac)) {
    LOG(WARNING) << "Error calculating CMAC digest";
    return false;
  }

  if (std::memcmp(&p_Output[0], &s_CalculatedCmac[0], s_CalculatedCmac.size()) != 0) {
    LOG(WARNING) << "CMAC digest does not match";
    return false;
  }

  return true;
}

static bool DecryptPatch(const unsigned char *p_Input, size_t p_InputLen, std::vector<unsigned char> &p_Output) {
  GetKeyToVariable("SYSCON", "PATCH_AES_KEY", s_AesKey);
  GetKeyToVariable("SYSCON", "PATCH_IV", s_Iv);
  GetKeyToVariable("SYSCON", "PATCH_MAC_KEY", s_MacKey);

  return DecryptCommon(s_AesKey, GetKeySize("SYSCON", "PATCH_AES_KEY"), s_Iv, s_MacKey, GetKeySize("SYSCON", "PATCH_MAC_KEY"), p_Input, p_InputLen, p_Output);
}

static bool DecryptFull(const unsigned char *p_Input, size_t p_InputLen, std::vector<unsigned char> &p_Output) {
  GetKeyToVariable("SYSCON", "FULL_AES_KEY", s_AesKey);
  GetKeyToVariable("SYSCON", "FULL_IV", s_Iv);
  GetKeyToVariable("SYSCON", "FULL_MAC_KEY", s_MacKey);

  return DecryptCommon(s_AesKey, GetKeySize("SYSCON", "FULL_AES_KEY"), s_Iv, s_MacKey, GetKeySize("SYSCON", "FULL_MAC_KEY"), p_Input, p_InputLen, p_Output);
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

  if (!DecryptPatch(p_Input, p_InputLen, p_Output)) {
    LOG(WARNING) << "Input data is not a \"patch\" SYSCON image, attemping to decrypt as a \"full\" SYSCON image";
    if (!DecryptFull(p_Input, p_InputLen, p_Output)) {
      LOG(ERROR) << "Input data is not a SYSCON image";
      return false;
    }
  }

  return true;
}

static bool EncryptCommon(unsigned char *p_AesKey, size_t p_AesLen, unsigned char *p_Iv, unsigned char *p_MacKey, size_t p_MacLen, const unsigned char *p_Input, size_t p_InputLen, std::vector<unsigned char> &p_Output) {
  VLOG(3) << "AES_KEY:\n" << HexDump(p_AesKey, p_AesLen);
  VLOG(3) << "IV:\n" << HexDump(p_Iv, 0x10);
  VLOG(3) << "MAC_KEY:\n" << HexDump(p_MacKey, p_MacLen);

  p_Output.clear();
  p_Output.shrink_to_fit();

  std::vector<unsigned char> s_CompiledInput;
  Cmac(p_MacKey, p_MacLen, &p_Input[0], p_InputLen, s_CompiledInput);

  s_CompiledInput.insert(s_CompiledInput.begin(), &p_Input[0], &p_Input[p_InputLen]);

  if (AesEncryptCbc(p_AesKey, p_AesLen, p_Iv, &s_CompiledInput[0], s_CompiledInput.size(), p_Output) != p_InputLen) {
    LOG(ERROR) << "Error encrypting data";
    p_Output.clear();
    p_Output.shrink_to_fit();
    return false;
  }

  return true;
}

static bool EncryptPatch(const unsigned char *p_Input, size_t p_InputLen, std::vector<unsigned char> &p_Output) {
  GetKeyToVariable("SYSCON", "PATCH_AES_KEY", s_AesKey);
  GetKeyToVariable("SYSCON", "PATCH_IV", s_Iv);
  GetKeyToVariable("SYSCON", "PATCH_MAC_KEY", s_MacKey);

  return EncryptCommon(s_AesKey, GetKeySize("SYSCON", "PATCH_AES_KEY"), s_Iv, s_MacKey, GetKeySize("SYSCON", "PATCH_MAC_KEY"), p_Input, p_InputLen, p_Output);
}

static bool EncryptFull(const unsigned char *p_Input, size_t p_InputLen, std::vector<unsigned char> &p_Output) {
  GetKeyToVariable("SYSCON", "FULL_AES_KEY", s_AesKey);
  GetKeyToVariable("SYSCON", "FULL_IV", s_Iv);
  GetKeyToVariable("SYSCON", "FULL_MAC_KEY", s_MacKey);

  return EncryptCommon(s_AesKey, GetKeySize("SYSCON", "FULL_AES_KEY"), s_Iv, s_MacKey, GetKeySize("SYSCON", "FULL_MAC_KEY"), p_Input, p_InputLen, p_Output);
}

bool Encrypt(const unsigned char *p_Input, size_t p_InputLen, std::vector<unsigned char> &p_Output) {
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

  bool s_Patch = false;
  uint32_t s_CmacLen = 0; // The static value `0x10` that can be assigned below is the MAC length per rfc4493

  if (CheckMagic(&p_Input[0], c_SysconBlnkMagic_, sizeof(c_SysconBlnkMagic_)) || //
      CheckMagic(&p_Input[0], c_SysconBaseMagic_, sizeof(c_SysconBaseMagic_)) || //
      CheckMagic(&p_Input[0], c_SysconSystMagic_, sizeof(c_SysconSystMagic_))) {
    s_Patch = false;
    s_CmacLen = 0;
  } else if (CheckMagic(&p_Input[0x10], c_SysconBlnkMagic_, sizeof(c_SysconBlnkMagic_)) || //
             CheckMagic(&p_Input[0x10], c_SysconBaseMagic_, sizeof(c_SysconBaseMagic_)) || //
             CheckMagic(&p_Input[0x10], c_SysconSystMagic_, sizeof(c_SysconSystMagic_))) {
    s_Patch = false;
    s_CmacLen = 0x10;
  } else if (CheckMagic(&p_Input[0], c_SysconPtchMagic_, sizeof(c_SysconPtchMagic_))) {
    s_Patch = true;
    s_CmacLen = 0;
  } else if (CheckMagic(&p_Input[0x10], c_SysconPtchMagic_, sizeof(c_SysconPtchMagic_))) {
    s_Patch = true;
    s_CmacLen = 0x10;
  } else {
    LOG(ERROR) << "Input data is not a SYSCON image";
    return false;
  }

  if (s_Patch) {
    if (p_InputLen > 0x7F0 + s_CmacLen) { // Max size is 0x800 with CMAC
      LOG(ERROR) << "Input length is invalid";
      return false;
    }
    return EncryptPatch(p_Input + s_CmacLen, p_InputLen - s_CmacLen, p_Output);
  }

  if (p_InputLen > UINT32_MAX) { // TODO: Check for ACTUAL valid max length
    LOG(ERROR) << "Input length is invalid";
    return false;
  }
  return EncryptFull(p_Input + s_CmacLen, p_InputLen - s_CmacLen, p_Output);
}
} // namespace syscon
