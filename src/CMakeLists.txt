# --- pam_tpm_ecc shared module ---

add_library(pam_tpm_ecc SHARED
    pam_tpm_ecc.c
)

target_compile_definitions(pam_tpm_ecc PRIVATE
    _GNU_SOURCE
    $<$<CONFIG:Release>:_FORTIFY_SOURCE=2>
)

target_include_directories(pam_tpm_ecc PRIVATE
    ${TSS2_INCLUDE_DIRS}
    ${OPENSSL_INCLUDE_DIR}
)

target_link_libraries(pam_tpm_ecc PRIVATE
    ${TSS2_LIBRARIES}
    OpenSSL::Crypto
    OpenSSL::SSL
    ${PAM_LIB}
)

# .so goes into build/src/, but PAM looks for bare module name.
# Supply a descriptive output name (the target name is already correct).
set_target_properties(pam_tpm_ecc PROPERTIES
    PREFIX ""
    SUFFIX ".so"
)

install(TARGETS pam_tpm_ecc
    LIBRARY DESTINATION lib/security
)
