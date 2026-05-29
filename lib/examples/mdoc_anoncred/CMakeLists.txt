add_library(mdoc_anoncred_demo_lib
  builder/cbor_encode.cc
  builder/input.cc
  builder/issue_custom.cc
  shared/crypto.cc
  shared/files.cc
  shared/interactive.cc
  shared/mdoc_demo.cc
  shared/request_codec.cc
  issuer/issue.cc
  holder/prove.cc
  verifier/verify.cc)

target_link_libraries(mdoc_anoncred_demo_lib mdoc)

target_include_directories(mdoc_anoncred_demo_lib PUBLIC ${proofs_SOURCE_DIR})

add_executable(mdoc_anoncred_issuer issuer/main.cc)
target_link_libraries(mdoc_anoncred_issuer mdoc_anoncred_demo_lib)

add_executable(mdoc_anoncred_holder holder/main.cc)
target_link_libraries(mdoc_anoncred_holder mdoc_anoncred_demo_lib)

add_executable(mdoc_anoncred_verifier verifier/main.cc)
target_link_libraries(mdoc_anoncred_verifier mdoc_anoncred_demo_lib)

add_executable(mdoc_anoncred_console console/main.cc)
target_link_libraries(mdoc_anoncred_console mdoc_anoncred_demo_lib)

if(PROOFS_BUILD_TESTS)
  add_executable(mdoc_anoncred_demo_test demo_test.cc)
  target_link_libraries(mdoc_anoncred_demo_test mdoc_anoncred_demo_lib)
  proofs_add_testing_libraries(mdoc_anoncred_demo_test)
endif()
