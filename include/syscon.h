#ifndef SYSCON_H_
#define SYSCON_H_

#include <cstddef>
#include <vector>

namespace syscon {
bool Decrypt(const unsigned char *p_Input, size_t p_InputLen, std::vector<unsigned char> &p_Output);
bool Encrypt(const unsigned char *p_Input, size_t p_InputLen, std::vector<unsigned char> &p_Output);

const char c_SysconBlnkMagic_[0x4]{'\x42', '\x4C', '\x4E', '\x4B'};
const char c_SysconBaseMagic_[0x4]{'\x42', '\x41', '\x53', '\x45'};
const char c_SysconSystMagic_[0x4]{'\x53', '\x59', '\x53', '\x54'};
const char c_SysconPtchMagic_[0x4]{'\x50', '\x54', '\x43', '\x48'};
} // namespace syscon

#endif
