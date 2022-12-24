#ifndef CRYPTO_H_
#define CRYPTO_H_

#include <cstddef>
#include <cstdint>
#include <vector>

#include <openssl/rsa.h>

template <typename I = size_t>
inline I align_up(I x, I align = 16);
template <typename I = size_t>
inline I align_down(I x, I align = 16);

bool RsaPkcs1V15Verify(const unsigned char *p_Modulus, size_t p_ModulusLen, const unsigned char *p_PublicExponent, size_t p_PublicExponentLen, const unsigned char *p_Input, size_t p_InputLen, const unsigned char *p_Signature, size_t p_SignatureLen);
bool RsaPublicEncrypt(const unsigned char *p_Modulus, size_t p_ModulusLen, const unsigned char *p_PublicExponent, size_t p_PublicExponentLen, const unsigned char *p_Input, size_t p_InputLen, std::vector<unsigned char> &p_Output, size_t p_OutputLen, int32_t p_Padding = RSA_NO_PADDING);

size_t AesEncryptEcb(const unsigned char *p_Key, size_t p_KeyLen, const unsigned char *p_Input, size_t p_InputLen, std::vector<unsigned char> &p_Output, int32_t p_Padding = 0);
size_t AesDecryptEcb(const unsigned char *p_Key, size_t p_KeyLen, const unsigned char *p_Input, size_t p_InputLen, std::vector<unsigned char> &p_Output, int32_t p_Padding = 0);
size_t AesEncryptCbc(const unsigned char *p_Key, size_t p_KeyLen, const unsigned char *p_Iv, const unsigned char *p_Input, size_t p_InputLen, std::vector<unsigned char> &p_Output, int32_t p_Padding = 0);
size_t AesDecryptCbc(const unsigned char *p_Key, size_t p_KeyLen, const unsigned char *p_Iv, const unsigned char *p_Input, size_t p_InputLen, std::vector<unsigned char> &p_Output, int32_t p_Padding = 0);
size_t AesEncryptCbcCts(const unsigned char *p_Key, size_t p_KeyLen, const unsigned char *p_Iv, const unsigned char *p_Input, size_t p_InputLen, std::vector<unsigned char> &p_Output);
size_t AesDecryptCbcCts(const unsigned char *p_Key, size_t p_KeyLen, const unsigned char *p_Iv, const unsigned char *p_Input, size_t p_InputLen, std::vector<unsigned char> &p_Output);

bool Sha256(const unsigned char *p_Input, size_t p_InputLen, std::vector<unsigned char> &p_Output);
bool HmacSha1(const unsigned char *p_Key, int32_t p_KeyLen, const unsigned char *p_Input, size_t p_InputLen, std::vector<unsigned char> &p_Output);
bool HmacSha256(const unsigned char *p_Key, int32_t p_KeyLen, const unsigned char *p_Input, size_t p_InputLen, std::vector<unsigned char> &p_Output);
bool Cmac(const unsigned char *p_Key, int32_t p_KeyLen, const unsigned char *p_Input, size_t p_InputLen, std::vector<unsigned char> &p_Output);

#endif
