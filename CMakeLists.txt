cmake_minimum_required(VERSION 3.16)
project(pam_tpm_ecc C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# --- hardening flags ---
add_compile_options(
    -Wall -Wextra -Wpedantic
    -fstack-protector-strong
)

# Debug / Release optimisation
set(CMAKE_C_FLAGS_DEBUG   "-O0 -g")
set(CMAKE_C_FLAGS_RELEASE "-O2 -DNDEBUG")

add_link_options(
    -Wl,-z,relro -Wl,-z,now
)

# --- dependencies ---
find_package(PkgConfig REQUIRED)

pkg_check_modules(TSS2 REQUIRED
    tss2-esys
    tss2-rc
    tss2-mu
    tss2-tctildr
)

find_package(OpenSSL REQUIRED)
find_library(PAM_LIB pam REQUIRED)

# --- subdirectories ---
add_subdirectory(src)
add_subdirectory(test)
