# --- test_verify — unit tests (no TPM required) ---

add_executable(test_verify
    test_verify.c
)

target_compile_definitions(test_verify PRIVATE _GNU_SOURCE)

target_link_libraries(test_verify PRIVATE
    OpenSSL::Crypto
    OpenSSL::SSL
)

# --- tpm_sign_test — standalone ESYS sign diagnostic ---

add_executable(tpm_sign_test
    tpm_sign_test.c
)

target_compile_definitions(tpm_sign_test PRIVATE _GNU_SOURCE)

target_include_directories(tpm_sign_test PRIVATE
    ${TSS2_INCLUDE_DIRS}
)

target_link_libraries(tpm_sign_test PRIVATE
    ${TSS2_LIBRARIES}
    OpenSSL::Crypto
)

# --- CTest integration ---
enable_testing()

add_test(NAME unit
    COMMAND test_verify
)

add_test(NAME integration
    COMMAND bash test.sh
    WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
)
