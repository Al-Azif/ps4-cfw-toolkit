cmake_minimum_required(VERSION 3.10.2)

add_library(CFW
    ${CMAKE_SOURCE_DIR}/src/common.cc
    ${CMAKE_SOURCE_DIR}/src/crypto.cc
    ${CMAKE_SOURCE_DIR}/src/eap.cc
    ${CMAKE_SOURCE_DIR}/src/emc.cc
    ${CMAKE_SOURCE_DIR}/src/key_store.cc
    ${CMAKE_SOURCE_DIR}/src/patch.cc
    ${CMAKE_SOURCE_DIR}/src/syscon.cc
)

# EAP KBL
project(eap
    VERSION 0.0.1
    DESCRIPTION "Decrypts/Encrypts EAP KBL (Kernel Boot Loader) images."
    HOMEPAGE_URL "https://github.com/Al-Azif/ps4-cfw-toolkit"
    LANGUAGES CXX
)

configure_file(${CMAKE_SOURCE_DIR}/include/cmake_vars_eap.h.in ${CMAKE_SOURCE_DIR}/include/cmake_vars_eap.h @ONLY)

add_executable(eap ${CMAKE_SOURCE_DIR}/src/main_eap.cc)
target_link_libraries(eap CFW)

target_link_libraries(eap -lglog) # TODO
target_link_libraries(eap gflags)
target_link_libraries(eap OpenSSL::SSL)
target_link_libraries(eap OpenSSL::Crypto)

# EAP Kernel
project(eapk
    VERSION 0.0.1
    DESCRIPTION "Decrypts/Encrypts EAP Kernel images."
    HOMEPAGE_URL "https://github.com/Al-Azif/ps4-cfw-toolkit"
    LANGUAGES CXX
)

configure_file(${CMAKE_SOURCE_DIR}/include/cmake_vars_eapk.h.in ${CMAKE_SOURCE_DIR}/include/cmake_vars_eapk.h @ONLY)

add_executable(eapk ${CMAKE_SOURCE_DIR}/src/main_eapk.cc)
target_link_libraries(eapk CFW)

target_link_libraries(eapk -lglog) # TODO
target_link_libraries(eapk gflags)
target_link_libraries(eapk OpenSSL::SSL)
target_link_libraries(eapk OpenSSL::Crypto)

# EMC
project(emc
    VERSION 0.0.1
    DESCRIPTION "Decrypts/Encrypts EMC images. Can apply \\\"Godmode\\\" patches during either operation."
    HOMEPAGE_URL "https://github.com/Al-Azif/ps4-cfw-toolkit"
    LANGUAGES CXX
)

configure_file(${CMAKE_SOURCE_DIR}/include/cmake_vars_emc.h.in ${CMAKE_SOURCE_DIR}/include/cmake_vars_emc.h @ONLY)

add_executable(emc ${CMAKE_SOURCE_DIR}/src/main_emc.cc)
target_link_libraries(emc CFW)

target_link_libraries(emc -lglog) # TODO
target_link_libraries(emc gflags)
target_link_libraries(emc OpenSSL::SSL)
target_link_libraries(emc OpenSSL::Crypto)

# SYSCON
project(syscon
    VERSION 0.0.1
    DESCRIPTION "Decrypts/Encrypts SYSCON images."
    HOMEPAGE_URL "https://github.com/Al-Azif/ps4-cfw-toolkit"
    LANGUAGES CXX
)

configure_file(${CMAKE_SOURCE_DIR}/include/cmake_vars_syscon.h.in ${CMAKE_SOURCE_DIR}/include/cmake_vars_syscon.h @ONLY)

add_executable(syscon ${CMAKE_SOURCE_DIR}/src/main_syscon.cc)
target_link_libraries(syscon CFW)

target_link_libraries(syscon -lglog) # TODO
target_link_libraries(syscon gflags)
target_link_libraries(syscon OpenSSL::SSL)
target_link_libraries(syscon OpenSSL::Crypto)
