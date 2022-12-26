#include "crypto.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <vector>

#include <glog/logging.h>
#include <openssl/aes.h>
#include <openssl/bn.h>
#include <openssl/cmac.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>

#include "banned.h"

template <typename I>
inline I align_up(I x, I align) {
  auto y{std::max(x, align)};
  return (y + (align - 1)) & ~(align - 1);
}

template <typename I>
inline I align_down(I x, I align) {
  auto y{std::max(x, align)};
  return y & ~(align - 1);
}

bool RsaPkcs1V15Verify(const unsigned char *p_Modulus, size_t p_ModulusLen, const unsigned char *p_PublicExponent, size_t p_PublicExponentLen, const unsigned char *p_Input, size_t p_InputLen, const unsigned char *p_Signature, size_t p_SignatureLen) {
  if (p_Modulus == nullptr) {
    LOG(ERROR) << "Modulus data is NULL";
    return false;
  }
  if (p_ModulusLen == 0) {
    LOG(ERROR) << "Modulus length is zero";
    return false;
  }
  if (p_PublicExponent == nullptr) {
    LOG(ERROR) << "Public Exponent data is NULL";
    return false;
  }
  if (p_PublicExponentLen == 0) {
    LOG(ERROR) << "Public Exponent length is zero";
    return false;
  }
  if (p_Input == nullptr) {
    LOG(ERROR) << "Input data is NULL";
    return false;
  }
  if (p_InputLen == 0) {
    LOG(ERROR) << "Input length is zero";
    return false;
  }
  if (p_Signature == nullptr) {
    LOG(ERROR) << "Signature data is NULL";
    return false;
  }
  if (p_SignatureLen == 0) {
    LOG(ERROR) << "Signature length is zero";
    return false;
  }

  EVP_MD_CTX *s_Ctx{EVP_MD_CTX_new()};
  EVP_PKEY *s_Pkey{EVP_PKEY_new()};
  RSA *s_Rsa{RSA_new()};
  BIGNUM *s_BnModulus{BN_new()};
  BIGNUM *s_BnPublicExponent{BN_new()};

  if (s_Ctx == nullptr) {
    LOG(ERROR) << "EVP_MD_CTX_new";
    goto fail;
  }
  if (s_Pkey == nullptr) {
    LOG(ERROR) << "EVP_PKEY_new";
    goto fail;
  }
  if (s_Rsa == nullptr) {
    LOG(ERROR) << "RSA_new";
    goto fail;
  }
  if (s_BnModulus == nullptr) {
    LOG(ERROR) << "BN_new";
    goto fail;
  }
  if (s_BnPublicExponent == nullptr) {
    LOG(ERROR) << "BN_new";
    goto fail;
  }

  BN_bin2bn(p_Modulus, p_ModulusLen, s_BnModulus);
  BN_bin2bn(p_PublicExponent, p_PublicExponentLen, s_BnPublicExponent);

  RSA_set0_key(s_Rsa, BN_dup(s_BnModulus), BN_dup(s_BnPublicExponent), NULL);

  BN_free(s_BnModulus); // Does not need `if (s_BnModulus != nullptr)` as it's checked against nullptr above
  s_BnModulus = nullptr;
  BN_free(s_BnPublicExponent); // Does not need `if (s_BnPublicExponent != nullptr)` as it's checked against nullptr above
  s_BnPublicExponent = nullptr;

  if (EVP_PKEY_assign_RSA(s_Pkey, RSAPublicKey_dup(s_Rsa)) != 1) {
    LOG(ERROR) << "EVP_PKEY_assign_RSA";
    goto fail;
  }

  RSA_free(s_Rsa); // Does not need `if (s_Rsa != nullptr)` as it's checked against NULL above
  s_Rsa = nullptr;

  if (EVP_DigestVerifyInit(s_Ctx, NULL, NULL, NULL, s_Pkey) != 1) {
    LOG(ERROR) << "EVP_DigestVerifyInit";
    goto fail;
  }

  if (EVP_DigestVerifyUpdate(s_Ctx, p_Input, p_InputLen) != 1) {
    LOG(ERROR) << "EVP_DigestVerifyUpdate";
    goto fail;
  }

  if (EVP_DigestVerifyFinal(s_Ctx, p_Signature, p_SignatureLen) != 1) {
    LOG(ERROR) << "EVP_DigestVerifyFinal";
    goto fail;
  }

  EVP_PKEY_free(s_Pkey); // Does not need `if (s_Pkey != nullptr)` as it's checked against nullptr above
  s_Pkey = nullptr;
  EVP_MD_CTX_free(s_Ctx); // Does not need `if (s_Ctx != nullptr)` as it's checked against nullptr above
  s_Ctx = nullptr;

  return true;

fail:
  if (s_BnModulus != nullptr) {
    BN_free(s_BnModulus);
    s_BnModulus = nullptr;
  }
  if (s_BnPublicExponent != nullptr) {
    BN_free(s_BnPublicExponent);
    s_BnPublicExponent = nullptr;
  }
  if (s_Rsa != nullptr) {
    RSA_free(s_Rsa);
    s_Rsa = nullptr;
  }
  if (s_Pkey != nullptr) {
    EVP_PKEY_free(s_Pkey);
    s_Pkey = nullptr;
  }
  if (s_Ctx != nullptr) {
    EVP_MD_CTX_free(s_Ctx);
    s_Ctx = nullptr;
  }

  return false;
}

bool RsaPublicEncrypt(const unsigned char *p_Modulus, size_t p_ModulusLen, const unsigned char *p_PublicExponent, size_t p_PublicExponentLen, const unsigned char *p_Input, size_t p_InputLen, std::vector<unsigned char> &p_Output, size_t p_OutputLen, int32_t p_Padding) {
  if (p_Input == &p_Output[0]) {
    LOG(ERROR) << "Input is at the same location as output";
    return false;
  }

  p_Output.clear();
  p_Output.shrink_to_fit();

  if (p_Modulus == nullptr) {
    LOG(ERROR) << "Modulus data is NULL";
    return false;
  }
  if (p_ModulusLen == 0) {
    LOG(ERROR) << "Modulus length is zero";
    return false;
  }
  if (p_PublicExponent == nullptr) {
    LOG(ERROR) << "Public Exponent data is NULL";
    return false;
  }
  if (p_PublicExponentLen == 0) {
    LOG(ERROR) << "Public Exponent length is zero";
    return false;
  }
  if (p_Input == nullptr) {
    LOG(ERROR) << "Input data is NULL";
    return false;
  }
  if (p_InputLen == 0) {
    LOG(ERROR) << "Input length is zero";
    return false;
  }
  if (p_OutputLen == 0) {
    LOG(ERROR) << "Output length is zero";
    return false;
  }
  // The pad parameter can take the following values:
  //   - RSA_PKCS1_PADDING for PKCS#1 padding
  //   - RSA_NO_PADDING for no padding
  //   - RSA_PKCS1_OAEP_PADDING for OAEP padding (encrypt and decrypt only)
  //   - RSA_X931_PADDING for X9.31 padding (signature operations only)
  //   - RSA_PKCS1_PSS_PADDING (sign and verify only)
  //   - RSA_PKCS1_WITH_TLS_PADDING for TLS RSA ClientKeyExchange message padding (decryption only)
  if (p_Padding != RSA_PKCS1_PADDING && p_Padding != RSA_NO_PADDING && p_Padding != RSA_PKCS1_OAEP_PADDING) {
    LOG(ERROR) << "Invalid padding option";
    return false;
  }

  EVP_PKEY_CTX *s_Ctx{nullptr};
  EVP_PKEY *s_Pkey{EVP_PKEY_new()};
  RSA *s_Rsa{RSA_new()};
  BIGNUM *s_BnModulus{BN_new()};
  BIGNUM *s_BnPublicExponent{BN_new()};
  p_Output.resize(p_OutputLen, '\0');

  if (s_Pkey == nullptr) {
    LOG(ERROR) << "EVP_PKEY_new";
    goto fail;
  }
  if (s_Rsa == nullptr) {
    LOG(ERROR) << "RSA_new";
    goto fail;
  }
  if (s_BnModulus == nullptr) {
    LOG(ERROR) << "BN_new";
    goto fail;
  }
  if (s_BnPublicExponent == nullptr) {
    LOG(ERROR) << "BN_new";
    goto fail;
  }

  BN_bin2bn(p_Modulus, p_ModulusLen, s_BnModulus);
  BN_bin2bn(p_PublicExponent, p_PublicExponentLen, s_BnPublicExponent);

  RSA_set0_key(s_Rsa, BN_dup(s_BnModulus), BN_dup(s_BnPublicExponent), NULL);

  BN_free(s_BnModulus); // Does not need `if (s_BnModulus != nullptr)` as it's checked against nullptr above
  s_BnModulus = nullptr;
  BN_free(s_BnPublicExponent); // Does not need `if (s_BnPublicExponent != nullptr)` as it's checked against nullptr above
  s_BnPublicExponent = nullptr;

  if (EVP_PKEY_assign_RSA(s_Pkey, RSAPublicKey_dup(s_Rsa)) != 1) {
    LOG(ERROR) << "EVP_PKEY_assign_RSA";
    goto fail;
  }

  RSA_free(s_Rsa); // Does not need `if (s_Rsa != nullptr)` as it's checked against nullptr above
  s_Rsa = nullptr;

  s_Ctx = EVP_PKEY_CTX_new(s_Pkey, NULL);
  if (s_Ctx == NULL) {
    LOG(ERROR) << "EVP_PKEY_CTX_new";
    goto fail;
  }

  if (EVP_PKEY_encrypt_init(s_Ctx) != 1) {
    LOG(ERROR) << "EVP_PKEY_encrypt_init";
    goto fail;
  }

  if (EVP_PKEY_CTX_set_rsa_padding(s_Ctx, p_Padding) != 1) {
    LOG(ERROR) << "EVP_PKEY_CTX_set_rsa_padding";
    goto fail;
  }

  if (EVP_PKEY_encrypt(s_Ctx, &p_Output[0], &p_OutputLen, p_Input, p_InputLen) != 1) {
    LOG(ERROR) << "EVP_PKEY_encrypt";
    goto fail;
  }

  EVP_PKEY_free(s_Pkey); // Does not need `if (s_Pkey != nullptr)` as it's checked against nullptr above
  s_Pkey = nullptr;
  EVP_PKEY_CTX_free(s_Ctx); // Does not need `if (s_Ctx != nullptr)` as it's checked against nullptr above
  s_Ctx = nullptr;

  // Already unsigned
  // if (p_OutputLen < 0) {
  //   return 0;
  // }

  return true;

fail:
  p_Output.clear();
  p_Output.shrink_to_fit();

  if (s_BnModulus != nullptr) {
    BN_free(s_BnModulus);
    s_BnModulus = nullptr;
  }
  if (s_BnPublicExponent != nullptr) {
    BN_free(s_BnPublicExponent);
    s_BnPublicExponent = nullptr;
  }
  if (s_Rsa != nullptr) {
    RSA_free(s_Rsa);
    s_Rsa = nullptr;
  }
  if (s_Pkey != nullptr) {
    EVP_PKEY_free(s_Pkey);
    s_Pkey = nullptr;
  }
  if (s_Ctx != nullptr) {
    EVP_PKEY_CTX_free(s_Ctx);
    s_Ctx = nullptr;
  }

  return false;
}

size_t AesEncryptEcb(const unsigned char *p_Key, size_t p_KeyLen, const unsigned char *p_Input, size_t p_InputLen, std::vector<unsigned char> &p_Output, int32_t p_Padding) {
  if (p_Input == &p_Output[0]) {
    LOG(ERROR) << "Input is at the same location as output";
    return 0;
  }

  p_Output.clear();
  p_Output.shrink_to_fit();

  if (p_Key == nullptr) {
    LOG(ERROR) << "Key data is NULL";
    return 0;
  }
  if (p_KeyLen == 0) {
    LOG(ERROR) << "Key length is zero";
    return 0;
  }
  if (p_Input == nullptr) {
    LOG(ERROR) << "Input data is NULL";
    return 0;
  }
  if (p_InputLen == 0) {
    LOG(ERROR) << "Input length is zero";
    return 0;
  }
  // TODO: Check padding values
  // By default encryption operations are padded using standard block padding
  // and the padding is checked and removed when decrypting. If the pad
  // parameter is zero then no padding is performed, the total amount of data
  // encrypted or decrypted must then be a multiple of the block size or an
  // error will occur.

  EVP_CIPHER_CTX *s_Ctx{EVP_CIPHER_CTX_new()};
  int32_t s_Len{0};
  int32_t s_CiphertextLen{0};
  p_Output.resize(align_up(p_InputLen, static_cast<size_t>(AES_BLOCK_SIZE)), '\0');

  if (s_Ctx == nullptr) {
    LOG(ERROR) << "EVP_CIPHER_CTX_new";
    goto fail;
  }

  if (p_KeyLen == 0x10) {
    if (EVP_EncryptInit_ex(s_Ctx, EVP_aes_128_ecb(), NULL, p_Key, NULL) != 1) {
      LOG(ERROR) << "EVP_EncryptInit_ex";
      goto fail;
    }
  } else if (p_KeyLen == 0x18) {
    if (EVP_EncryptInit_ex(s_Ctx, EVP_aes_192_ecb(), NULL, p_Key, NULL) != 1) {
      LOG(ERROR) << "EVP_EncryptInit_ex";
      goto fail;
    }
  } else if (p_KeyLen == 0x20) {
    if (EVP_EncryptInit_ex(s_Ctx, EVP_aes_256_ecb(), NULL, p_Key, NULL) != 1) {
      LOG(ERROR) << "EVP_EncryptInit_ex";
      goto fail;
    }
  } else {
    LOG(ERROR) << "Unknown key size";
    goto fail;
  }

  if (EVP_CIPHER_CTX_set_padding(s_Ctx, p_Padding) != 1) {
    LOG(ERROR) << "EVP_CIPHER_CTX_set_padding";
    goto fail;
  }

  if (EVP_EncryptUpdate(s_Ctx, &p_Output[0], &s_Len, p_Input, p_InputLen) != 1) {
    LOG(ERROR) << "EVP_EncryptUpdate";
    goto fail;
  }
  s_CiphertextLen = s_Len;

  if (EVP_EncryptFinal_ex(s_Ctx, &p_Output[s_Len], &s_Len) != 1) {
    LOG(ERROR) << "EVP_EncryptFinal_ex";
    goto fail;
  }
  s_CiphertextLen += s_Len;

  EVP_CIPHER_CTX_free(s_Ctx); // Does not need `if (s_Ctx != nullptr)` as it's checked against nullptr above
  s_Ctx = nullptr;

  if (s_CiphertextLen < 0) {
    goto fail;
  }

  return s_CiphertextLen;

fail:
  p_Output.clear();
  p_Output.shrink_to_fit();

  if (s_Ctx != nullptr) {
    EVP_CIPHER_CTX_free(s_Ctx);
    s_Ctx = nullptr;
  }

  return 0;
}

size_t AesDecryptEcb(const unsigned char *p_Key, size_t p_KeyLen, const unsigned char *p_Input, size_t p_InputLen, std::vector<unsigned char> &p_Output, int32_t p_Padding) {
  if (p_Input == &p_Output[0]) {
    LOG(ERROR) << "Input is at the same location as output";
    return 0;
  }

  p_Output.clear();
  p_Output.shrink_to_fit();

  if (p_Key == nullptr) {
    LOG(ERROR) << "Key data is NULL";
    return 0;
  }
  if (p_KeyLen == 0) {
    LOG(ERROR) << "Key length is zero";
    return 0;
  }
  if (p_Input == nullptr) {
    LOG(ERROR) << "Input data is NULL";
    return 0;
  }
  if (p_InputLen == 0) {
    LOG(ERROR) << "Input length is zero";
    return 0;
  }
  // TODO: Check padding values
  // By default encryption operations are padded using standard block padding
  // and the padding is checked and removed when decrypting. If the pad
  // parameter is zero then no padding is performed, the total amount of data
  // encrypted or decrypted must then be a multiple of the block size or an
  // error will occur.

  EVP_CIPHER_CTX *s_Ctx{EVP_CIPHER_CTX_new()};
  int32_t s_Len{0};
  int32_t s_PlaintextLen{0};
  p_Output.resize(align_up(p_InputLen, static_cast<size_t>(AES_BLOCK_SIZE)), '\0');

  if (s_Ctx == nullptr) {
    LOG(ERROR) << "EVP_CIPHER_CTX_new";
    goto fail;
  }

  if (p_KeyLen == 0x10) {
    if (EVP_DecryptInit_ex(s_Ctx, EVP_aes_128_ecb(), NULL, p_Key, NULL) != 1) {
      LOG(ERROR) << "EVP_DecryptInit_ex";
      goto fail;
    }
  } else if (p_KeyLen == 0x18) {
    if (EVP_DecryptInit_ex(s_Ctx, EVP_aes_192_ecb(), NULL, p_Key, NULL) != 1) {
      LOG(ERROR) << "EVP_DecryptInit_ex";
      goto fail;
    }
  } else if (p_KeyLen == 0x20) {
    if (EVP_DecryptInit_ex(s_Ctx, EVP_aes_256_ecb(), NULL, p_Key, NULL) != 1) {
      LOG(ERROR) << "EVP_DecryptInit_ex";
      goto fail;
    }
  } else {
    LOG(ERROR) << "Unknown key size";
    goto fail;
  }

  if (EVP_CIPHER_CTX_set_padding(s_Ctx, p_Padding) != 1) {
    LOG(ERROR) << "EVP_CIPHER_CTX_set_padding";
    goto fail;
  }

  if (EVP_DecryptUpdate(s_Ctx, &p_Output[0], &s_Len, p_Input, p_InputLen) != 1) {
    LOG(ERROR) << "EVP_DecryptUpdate";
    goto fail;
  }
  s_PlaintextLen = s_Len;

  if (EVP_DecryptFinal_ex(s_Ctx, &p_Output[s_Len], &s_Len) != 1) {
    LOG(ERROR) << "EVP_DecryptFinal_ex";
    goto fail;
  }
  s_PlaintextLen += s_Len;

  EVP_CIPHER_CTX_free(s_Ctx); // Does not need `if (s_Ctx != nullptr)` as it's checked against nullptr above
  s_Ctx = nullptr;

  if (s_PlaintextLen < 0) {
    goto fail;
  }

  return s_PlaintextLen;

fail:
  p_Output.clear();
  p_Output.shrink_to_fit();

  if (s_Ctx != nullptr) {
    EVP_CIPHER_CTX_free(s_Ctx);
    s_Ctx = nullptr;
  }

  return 0;
}

size_t AesEncryptCbc(const unsigned char *p_Key, size_t p_KeyLen, const unsigned char *p_Iv, const unsigned char *p_Input, size_t p_InputLen, std::vector<unsigned char> &p_Output, int32_t p_Padding) {
  if (p_Input == &p_Output[0]) {
    LOG(ERROR) << "Input is at the same location as output";
    return 0;
  }

  p_Output.clear();
  p_Output.shrink_to_fit();

  if (p_Key == nullptr) {
    LOG(ERROR) << "Key data is NULL";
    return 0;
  }
  if (p_KeyLen == 0) {
    LOG(ERROR) << "Key length is zero";
    return 0;
  }
  if (p_Iv == nullptr) {
    LOG(ERROR) << "IV is NULL";
    return 0;
  }
  if (p_Input == nullptr) {
    LOG(ERROR) << "Input data is NULL";
    return 0;
  }
  if (p_InputLen == 0) {
    LOG(ERROR) << "Input length is zero";
    return 0;
  }
  // TODO: Check padding values
  // By default encryption operations are padded using standard block padding
  // and the padding is checked and removed when decrypting. If the pad
  // parameter is zero then no padding is performed, the total amount of data
  // encrypted or decrypted must then be a multiple of the block size or an
  // error will occur.

  EVP_CIPHER_CTX *s_Ctx{EVP_CIPHER_CTX_new()};
  int32_t s_Len{0};
  int32_t s_CiphertextLen{0};
  p_Output.resize(align_up(p_InputLen, static_cast<size_t>(AES_BLOCK_SIZE)), '\0');

  if (s_Ctx == nullptr) {
    LOG(ERROR) << "EVP_CIPHER_CTX_new";
    goto fail;
  }

  if (p_KeyLen == 0x10) {
    if (EVP_EncryptInit_ex(s_Ctx, EVP_aes_128_cbc(), NULL, p_Key, p_Iv) != 1) {
      LOG(ERROR) << "EVP_EncryptInit_ex";
      goto fail;
    }
  } else if (p_KeyLen == 0x18) {
    if (EVP_EncryptInit_ex(s_Ctx, EVP_aes_192_cbc(), NULL, p_Key, p_Iv) != 1) {
      LOG(ERROR) << "EVP_EncryptInit_ex";
      goto fail;
    }
  } else if (p_KeyLen == 0x20) {
    if (EVP_EncryptInit_ex(s_Ctx, EVP_aes_256_cbc(), NULL, p_Key, p_Iv) != 1) {
      LOG(ERROR) << "EVP_EncryptInit_ex";
      goto fail;
    }
  } else {
    LOG(ERROR) << "Unknown key size";
    goto fail;
  }

  if (EVP_CIPHER_CTX_set_padding(s_Ctx, p_Padding) != 1) {
    LOG(ERROR) << "EVP_CIPHER_CTX_set_padding";
    goto fail;
  }

  if (EVP_EncryptUpdate(s_Ctx, &p_Output[0], &s_Len, p_Input, p_InputLen) != 1) {
    LOG(ERROR) << "EVP_EncryptUpdate";
    goto fail;
  }
  s_CiphertextLen = s_Len;

  if (EVP_EncryptFinal_ex(s_Ctx, &p_Output[s_Len], &s_Len) != 1) {
    LOG(ERROR) << "EVP_EncryptFinal_ex";
    goto fail;
  }
  s_CiphertextLen += s_Len;

  EVP_CIPHER_CTX_free(s_Ctx); // Does not need `if (s_Ctx != nullptr)` as it's checked against nullptr above
  s_Ctx = nullptr;

  if (s_CiphertextLen < 0) {
    goto fail;
  }

  return s_CiphertextLen;

fail:
  p_Output.clear();
  p_Output.shrink_to_fit();

  if (s_Ctx != nullptr) {
    EVP_CIPHER_CTX_free(s_Ctx);
    s_Ctx = nullptr;
  }

  return 0;
}

size_t AesDecryptCbc(const unsigned char *p_Key, size_t p_KeyLen, const unsigned char *p_Iv, const unsigned char *p_Input, size_t p_InputLen, std::vector<unsigned char> &p_Output, int32_t p_Padding) {
  if (p_Input == &p_Output[0]) {
    LOG(ERROR) << "Input is at the same location as output";
    return 0;
  }

  p_Output.clear();
  p_Output.shrink_to_fit();

  if (p_Key == nullptr) {
    LOG(ERROR) << "Key data is NULL";
    return 0;
  }
  if (p_KeyLen == 0) {
    LOG(ERROR) << "Key length is zero";
    return 0;
  }
  if (p_Iv == nullptr) {
    LOG(ERROR) << "IV is NULL";
    return 0;
  }
  if (p_Input == nullptr) {
    LOG(ERROR) << "Input data is NULL";
    return 0;
  }
  if (p_InputLen == 0) {
    LOG(ERROR) << "Input length is zero";
    return 0;
  }
  // TODO: Check padding values
  // By default encryption operations are padded using standard block padding
  // and the padding is checked and removed when decrypting. If the pad
  // parameter is zero then no padding is performed, the total amount of data
  // encrypted or decrypted must then be a multiple of the block size or an
  // error will occur.

  EVP_CIPHER_CTX *s_Ctx{EVP_CIPHER_CTX_new()};
  int32_t s_Len{0};
  int32_t s_PlaintextLen{0};
  p_Output.resize(align_up(p_InputLen, static_cast<size_t>(AES_BLOCK_SIZE)), '\0');

  if (s_Ctx == nullptr) {
    LOG(ERROR) << "EVP_CIPHER_CTX_new";
    goto fail;
  }

  if (p_KeyLen == 0x10) {
    if (EVP_DecryptInit_ex(s_Ctx, EVP_aes_128_cbc(), NULL, p_Key, p_Iv) != 1) {
      LOG(ERROR) << "EVP_DecryptInit_ex";
      goto fail;
    }
  } else if (p_KeyLen == 0x18) {
    if (EVP_DecryptInit_ex(s_Ctx, EVP_aes_192_cbc(), NULL, p_Key, p_Iv) != 1) {
      LOG(ERROR) << "EVP_DecryptInit_ex";
      goto fail;
    }
  } else if (p_KeyLen == 0x20) {
    if (EVP_DecryptInit_ex(s_Ctx, EVP_aes_256_cbc(), NULL, p_Key, p_Iv) != 1) {
      LOG(ERROR) << "EVP_DecryptInit_ex";
      goto fail;
    }
  } else {
    LOG(ERROR) << "Unknown key size";
    goto fail;
  }

  if (EVP_CIPHER_CTX_set_padding(s_Ctx, p_Padding) != 1) {
    LOG(ERROR) << "EVP_CIPHER_CTX_set_padding";
    goto fail;
  }

  if (EVP_DecryptUpdate(s_Ctx, &p_Output[0], &s_Len, p_Input, p_InputLen) != 1) {
    LOG(ERROR) << "EVP_DecryptUpdate";
    goto fail;
  }
  s_PlaintextLen = s_Len;

  if (EVP_DecryptFinal_ex(s_Ctx, &p_Output[s_Len], &s_Len) != 1) {
    LOG(ERROR) << "EVP_DecryptFinal_ex";
    goto fail;
  }
  s_PlaintextLen += s_Len;

  EVP_CIPHER_CTX_free(s_Ctx); // Does not need `if (s_Ctx != nullptr)` as it's checked against nullptr above
  s_Ctx = nullptr;

  if (s_PlaintextLen < 0) {
    goto fail;
  }

  return s_PlaintextLen;

fail:
  p_Output.clear();
  p_Output.shrink_to_fit();

  if (s_Ctx != nullptr) {
    EVP_CIPHER_CTX_free(s_Ctx);
    s_Ctx = nullptr;
  }

  return 0;
}

size_t AesEncryptCbcCts(const unsigned char *p_Key, size_t p_KeyLen, const unsigned char *p_Iv, const unsigned char *p_Input, size_t p_InputLen, std::vector<unsigned char> &p_Output) {
  if (p_Input == &p_Output[0]) {
    LOG(ERROR) << "Input is at the same location as output";
    return 0;
  }

  p_Output.clear();
  p_Output.shrink_to_fit();

  if (p_Key == nullptr) {
    LOG(ERROR) << "Key data is NULL";
    return 0;
  }
  if (p_KeyLen == 0) {
    LOG(ERROR) << "Key length is zero";
    return 0;
  }
  if (p_Iv == nullptr) {
    LOG(ERROR) << "IV is NULL";
    return 0;
  }
  if (p_Input == nullptr) {
    LOG(ERROR) << "Input data is NULL";
    return 0;
  }
  if (p_InputLen == 0) {
    LOG(ERROR) << "Input length is zero";
    return 0;
  }

  uint64_t s_NumDataLeft{p_InputLen};
  uint64_t s_Offset{0};
  std::vector<unsigned char> s_TempBlock;
  std::vector<unsigned char> s_TempIv;
  s_TempIv.insert(s_TempIv.begin(), &p_Iv[0], &p_Iv[0x10]);

  while (s_NumDataLeft >= AES_BLOCK_SIZE) {
    std::vector<unsigned char> s_InputBlock;
    for (uint32_t i{0}; i < AES_BLOCK_SIZE; i++) {
      s_InputBlock.push_back(p_Input[s_Offset + i] ^ s_TempIv[i]);
    }
    if (AesEncryptEcb(p_Key, p_KeyLen, &s_InputBlock[0], AES_BLOCK_SIZE, s_TempBlock) != AES_BLOCK_SIZE) {
      LOG(ERROR) << "Error decrypting data";
      goto fail;
    }
    p_Output.insert(p_Output.end(), s_TempBlock.begin(), s_TempBlock.end());
    std::copy(s_TempBlock.begin(), s_TempBlock.begin() + s_TempIv.size(), s_TempIv.begin());
    s_NumDataLeft -= AES_BLOCK_SIZE;
    s_Offset += AES_BLOCK_SIZE;
  }

  if (s_NumDataLeft > 0) {
    if (AesEncryptEcb(p_Key, p_KeyLen, &s_TempIv[0], AES_BLOCK_SIZE, s_TempBlock) != AES_BLOCK_SIZE) {
      LOG(ERROR) << "Error encrypting data";
      goto fail;
    }

    for (uint32_t i{0}; i < s_NumDataLeft; i++) {
      p_Output.push_back(p_Input[s_Offset + i] ^ s_TempBlock[i]);
    }
  }

  return p_Output.size();

fail:
  p_Output.clear();
  p_Output.shrink_to_fit();

  return 0;
}

size_t AesDecryptCbcCts(const unsigned char *p_Key, size_t p_KeyLen, const unsigned char *p_Iv, const unsigned char *p_Input, size_t p_InputLen, std::vector<unsigned char> &p_Output) {
  if (p_Input == &p_Output[0]) {
    LOG(ERROR) << "Input is at the same location as output";
    return 0;
  }

  p_Output.clear();
  p_Output.shrink_to_fit();

  if (p_Key == nullptr) {
    LOG(ERROR) << "Key data is NULL";
    return 0;
  }
  if (p_KeyLen == 0) {
    LOG(ERROR) << "Key length is zero";
    return 0;
  }
  if (p_Iv == nullptr) {
    LOG(ERROR) << "IV is NULL";
    return 0;
  }
  if (p_Input == nullptr) {
    LOG(ERROR) << "Input data is NULL";
    return 0;
  }
  if (p_InputLen == 0) {
    LOG(ERROR) << "Input length is zero";
    return 0;
  }

  uint64_t s_NumDataLeft{p_InputLen};
  uint64_t s_Offset{0};
  std::vector<unsigned char> s_TempBlock;
  std::vector<unsigned char> s_TempIv;
  s_TempIv.insert(s_TempIv.begin(), &p_Iv[0], &p_Iv[0x10]);

  while (s_NumDataLeft >= AES_BLOCK_SIZE) {
    if (AesDecryptEcb(p_Key, p_KeyLen, p_Input + s_Offset, AES_BLOCK_SIZE, s_TempBlock) != AES_BLOCK_SIZE) {
      LOG(ERROR) << "Error decrypting data";
      goto fail;
    }
    for (uint32_t i{0}; i < AES_BLOCK_SIZE; i++) {
      p_Output.push_back(s_TempBlock[i] ^ s_TempIv[i]);
    }
    std::copy(p_Input + s_Offset, p_Input + s_Offset + s_TempIv.size(), s_TempIv.begin());
    s_NumDataLeft -= AES_BLOCK_SIZE;
    s_Offset += AES_BLOCK_SIZE;
  }

  if (s_NumDataLeft > 0) {
    if (AesEncryptEcb(p_Key, p_KeyLen, &s_TempIv[0], AES_BLOCK_SIZE, s_TempBlock) != AES_BLOCK_SIZE) {
      LOG(ERROR) << "Error encrypting data";
      goto fail;
    }

    for (uint32_t i{0}; i < s_NumDataLeft; i++) {
      p_Output.push_back(p_Input[s_Offset + i] ^ s_TempBlock[i]);
    }
  }

  return p_Output.size();

fail:
  p_Output.clear();
  p_Output.shrink_to_fit();

  return 0;
}

bool Sha256(const unsigned char *p_Input, size_t p_InputLen, std::vector<unsigned char> &p_Output) {
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

  EVP_MD_CTX *s_Ctx{EVP_MD_CTX_new()};
  unsigned int s_DigestLen{SHA256_DIGEST_LENGTH};
  p_Output.resize(s_DigestLen, '\0');

  if (s_Ctx == nullptr) {
    LOG(ERROR) << "EVP_MD_CTX_new";
    goto fail;
  }

  if (EVP_DigestInit_ex(s_Ctx, EVP_sha256(), NULL) != 1) {
    LOG(ERROR) << "EVP_DigestInit_ex";
    goto fail;
  }

  if (EVP_DigestUpdate(s_Ctx, p_Input, p_InputLen) != 1) {
    LOG(ERROR) << "EVP_DigestUpdate";
    goto fail;
  }

  if (EVP_DigestFinal_ex(s_Ctx, &p_Output[0], &s_DigestLen) != 1) {
    LOG(ERROR) << "EVP_DigestFinal_ex";
    goto fail;
  }

  EVP_MD_CTX_free(s_Ctx); // Does not need `if (s_Ctx != nullptr)` as it's checked against nullptr above
  s_Ctx = nullptr;

  return true;

fail:
  p_Output.clear();
  p_Output.shrink_to_fit();

  if (s_Ctx != nullptr) {
    EVP_MD_CTX_free(s_Ctx);
    s_Ctx = nullptr;
  }

  return false;
}

bool HmacSha1(const unsigned char *p_Key, int32_t p_KeyLen, const unsigned char *p_Input, size_t p_InputLen, std::vector<unsigned char> &p_Output) {
  if (p_Input == &p_Output[0]) {
    LOG(ERROR) << "Input is at the same location as output";
    return false;
  }

  p_Output.clear();
  p_Output.shrink_to_fit();

  if (p_Key == nullptr) {
    LOG(ERROR) << "Input data is NULL";
    return false;
  }
  if (p_KeyLen <= 0) {
    LOG(ERROR) << "Input length is zero";
    return false;
  }
  if (p_Input == nullptr) {
    LOG(ERROR) << "Input data is NULL";
    return false;
  }
  if (p_InputLen == 0) {
    LOG(ERROR) << "Input length is zero";
    return false;
  }

  EVP_MD_CTX *s_Ctx{EVP_MD_CTX_new()};
  EVP_PKEY *s_Pkey{EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, p_Key, p_KeyLen)};
  size_t s_DigestLen{SHA_DIGEST_LENGTH};
  p_Output.resize(s_DigestLen, '\0');

  if (s_Ctx == nullptr) {
    LOG(ERROR) << "EVP_MD_CTX_new";
    goto fail;
  }
  if (s_Pkey == nullptr) {
    LOG(ERROR) << "EVP_PKEY_new_mac_key";
    goto fail;
  }

  if (EVP_DigestSignInit(s_Ctx, NULL, EVP_sha1(), NULL, s_Pkey) != 1) {
    LOG(ERROR) << "EVP_DigestSignInit";
    goto fail;
  }

  if (EVP_DigestSignUpdate(s_Ctx, p_Input, p_InputLen) != 1) {
    LOG(ERROR) << "EVP_DigestSignUpdate";
    goto fail;
  }

  if (EVP_DigestSignFinal(s_Ctx, &p_Output[0], &s_DigestLen) != 1) {
    LOG(ERROR) << "EVP_DigestSignFinal";
    goto fail;
  }

  EVP_MD_CTX_free(s_Ctx); // Does not need `if (s_Ctx != nullptr)` as it's checked against nullptr above
  s_Ctx = nullptr;
  EVP_PKEY_free(s_Pkey); // Does not need `if (s_Pkey != nullptr)` as it's checked against nullptr above
  s_Pkey = nullptr;

  return true;

fail:
  p_Output.clear();
  p_Output.shrink_to_fit();

  if (s_Ctx != nullptr) {
    EVP_MD_CTX_free(s_Ctx);
    s_Ctx = nullptr;
  }
  if (s_Pkey != nullptr) {
    EVP_PKEY_free(s_Pkey);
    s_Pkey = nullptr;
  }

  return false;
}

bool HmacSha256(const unsigned char *p_Key, int32_t p_KeyLen, const unsigned char *p_Input, size_t p_InputLen, std::vector<unsigned char> &p_Output) {
  if (p_Input == &p_Output[0]) {
    LOG(ERROR) << "Input is at the same location as output";
    return false;
  }

  p_Output.clear();
  p_Output.shrink_to_fit();

  if (p_Key == nullptr) {
    LOG(ERROR) << "Input data is NULL";
    return false;
  }
  if (p_KeyLen <= 0) {
    LOG(ERROR) << "Input length is zero";
    return false;
  }
  if (p_Input == nullptr) {
    LOG(ERROR) << "Input data is NULL";
    return false;
  }
  if (p_InputLen == 0) {
    LOG(ERROR) << "Input length is zero";
    return false;
  }

  EVP_MD_CTX *s_Ctx{EVP_MD_CTX_new()};
  EVP_PKEY *s_Pkey{EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, p_Key, p_KeyLen)};
  size_t s_DigestLen{SHA256_DIGEST_LENGTH};
  p_Output.resize(s_DigestLen, '\0');

  if (s_Ctx == nullptr) {
    LOG(ERROR) << "EVP_MD_CTX_new";
    goto fail;
  }
  if (s_Pkey == nullptr) {
    LOG(ERROR) << "EVP_PKEY_new_mac_key";
    goto fail;
  }

  if (EVP_DigestSignInit(s_Ctx, NULL, EVP_sha256(), NULL, s_Pkey) != 1) {
    LOG(ERROR) << "EVP_DigestSignInit";
    goto fail;
  }

  if (EVP_DigestSignUpdate(s_Ctx, p_Input, p_InputLen) != 1) {
    LOG(ERROR) << "EVP_DigestSignUpdate";
    goto fail;
  }

  if (EVP_DigestSignFinal(s_Ctx, &p_Output[0], &s_DigestLen) != 1) {
    LOG(ERROR) << "EVP_DigestSignFinal";
    goto fail;
  }

  EVP_MD_CTX_free(s_Ctx); // Does not need `if (s_Ctx != nullptr)` as it's checked against nullptr above
  s_Ctx = nullptr;
  EVP_PKEY_free(s_Pkey); // Does not need `if (s_Pkey != nullptr)` as it's checked against nullptr above
  s_Pkey = nullptr;

  return true;

fail:
  p_Output.clear();
  p_Output.shrink_to_fit();

  if (s_Ctx != nullptr) {
    EVP_MD_CTX_free(s_Ctx);
    s_Ctx = nullptr;
  }
  if (s_Pkey != nullptr) {
    EVP_PKEY_free(s_Pkey);
    s_Pkey = nullptr;
  }

  return false;
}

bool Cmac(const unsigned char *p_Key, int32_t p_KeyLen, const unsigned char *p_Input, size_t p_InputLen, std::vector<unsigned char> &p_Output) {
  // TODO: Can use EVP_MAC?
  if (p_Input == &p_Output[0]) {
    LOG(ERROR) << "Input is at the same location as output";
    return false;
  }

  p_Output.clear();
  p_Output.shrink_to_fit();

  if (p_Key == nullptr) {
    LOG(ERROR) << "Input data is NULL";
    return false;
  }
  if (p_KeyLen <= 0) {
    LOG(ERROR) << "Input length is zero";
    return false;
  }
  if (p_Input == nullptr) {
    LOG(ERROR) << "Input data is NULL";
    return false;
  }
  if (p_InputLen == 0) {
    LOG(ERROR) << "Input length is zero";
    return false;
  }

  EVP_MD_CTX *s_Ctx{EVP_MD_CTX_new()};
  EVP_PKEY_CTX *s_Kctx{EVP_PKEY_CTX_new_id(EVP_PKEY_CMAC, NULL)};
  EVP_PKEY *s_Pkey{nullptr};
  size_t s_DigestLen{static_cast<size_t>(p_KeyLen)};
  p_Output.resize(0x10, '\0'); // The static value `0x10` below is the MAC length per rfc4493

  if (s_Ctx == nullptr) {
    LOG(ERROR) << "EVP_MD_CTX_new";
    goto fail;
  }
  if (s_Kctx == nullptr) {
    LOG(ERROR) << "EVP_PKEY_CTX_new_id";
    goto fail;
  }

  if (EVP_PKEY_keygen_init(s_Kctx) != 1) {
    LOG(ERROR) << "EVP_PKEY_keygen_init";
    goto fail;
  }

  if (p_KeyLen == 0x10) {
    if (EVP_PKEY_CTX_ctrl(s_Kctx, -1, EVP_PKEY_OP_KEYGEN, EVP_PKEY_CTRL_CIPHER, 0, const_cast<EVP_CIPHER *>(EVP_aes_128_cbc())) <= 0) {
      LOG(ERROR) << "EVP_PKEY_CTX_ctrl";
      goto fail;
    }
  } else if (p_KeyLen == 0x18) {
    if (EVP_PKEY_CTX_ctrl(s_Kctx, -1, EVP_PKEY_OP_KEYGEN, EVP_PKEY_CTRL_CIPHER, 0, const_cast<EVP_CIPHER *>(EVP_aes_192_cbc())) <= 0) {
      LOG(ERROR) << "EVP_PKEY_CTX_ctrl";
      goto fail;
    }
  } else if (p_KeyLen == 0x20) {
    if (EVP_PKEY_CTX_ctrl(s_Kctx, -1, EVP_PKEY_OP_KEYGEN, EVP_PKEY_CTRL_CIPHER, 0, const_cast<EVP_CIPHER *>(EVP_aes_256_cbc())) <= 0) {
      LOG(ERROR) << "EVP_PKEY_CTX_ctrl";
      goto fail;
    }
  } else {
    LOG(ERROR) << "Unknown key size";
    goto fail;
  }

  if (EVP_PKEY_CTX_ctrl(s_Kctx, -1, EVP_PKEY_OP_KEYGEN, EVP_PKEY_CTRL_SET_MAC_KEY, p_KeyLen, const_cast<unsigned char *>(p_Key)) <= 0) {
    LOG(ERROR) << "EVP_PKEY_CTX_ctrl";
    goto fail;
  }

  if (EVP_PKEY_keygen(s_Kctx, &s_Pkey) != 1) {
    LOG(ERROR) << "EVP_PKEY_keygen";
    goto fail;
  }

  if (s_Pkey == nullptr) {
    LOG(ERROR) << "EVP_PKEY_keygen";
    goto fail;
  }

  if (EVP_DigestSignInit(s_Ctx, NULL, NULL, NULL, s_Pkey) != 1) {
    LOG(ERROR) << "EVP_DigestSignInit";
    goto fail;
  }

  if (EVP_DigestSignUpdate(s_Ctx, p_Input, p_InputLen) != 1) {
    LOG(ERROR) << "EVP_DigestSignUpdate";
    goto fail;
  }

  if (EVP_DigestSignFinal(s_Ctx, &p_Output[0], &s_DigestLen) != 1) {
    LOG(ERROR) << "EVP_DigestSignFinal";
    goto fail;
  }

  EVP_MD_CTX_free(s_Ctx); // Does not need `if (s_Ctx != nullptr)` as it's checked against nullptr above
  s_Ctx = nullptr;
  EVP_PKEY_CTX_free(s_Kctx); // Does not need `if (s_Kctx != nullptr)` as it's checked against nullptr above
  s_Kctx = nullptr;
  EVP_PKEY_free(s_Pkey); // Does not need `if (s_Pkey != nullptr)` as it's checked against nullptr above
  s_Pkey = nullptr;

  return true;

fail:
  p_Output.clear();
  p_Output.shrink_to_fit();

  if (s_Ctx != nullptr) {
    EVP_MD_CTX_free(s_Ctx);
    s_Ctx = nullptr;
  }
  if (s_Kctx != nullptr) {
    EVP_PKEY_CTX_free(s_Kctx);
    s_Kctx = nullptr;
  }
  if (s_Pkey != nullptr) {
    EVP_PKEY_free(s_Pkey);
    s_Pkey = nullptr;
  }

  return false;
}
