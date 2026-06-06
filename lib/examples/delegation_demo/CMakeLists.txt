add_library(delegation_demo_lib
  shared/delegation_crypto.cc
  shared/delegation_revocation.cc
  shared/delegation_files.cc
  alice/delegate.cc
  agent/present.cc
  verifier/verify.cc)

target_link_libraries(delegation_demo_lib
  mdoc_anoncred_demo_lib
  mdoc)

target_include_directories(delegation_demo_lib PUBLIC ${proofs_SOURCE_DIR})

# Module A: Issuer（直接复用现有 mdoc_anoncred issuer 逻辑）
add_executable(delegation_demo_issuer issuer/main.cc)
target_link_libraries(delegation_demo_issuer mdoc_anoncred_demo_lib)

# Module B: Alice（委托生成）
add_executable(delegation_demo_alice alice/main.cc)
target_link_libraries(delegation_demo_alice delegation_demo_lib)

# Module C: Agent（代理展示）
add_executable(delegation_demo_agent agent/main.cc)
target_link_libraries(delegation_demo_agent delegation_demo_lib)

# Module D: Verifier（请求+验证）
add_executable(delegation_demo_verifier verifier/main.cc)
target_link_libraries(delegation_demo_verifier delegation_demo_lib)

# 端到端测试
if(PROOFS_BUILD_TESTS AND EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/delegation_demo_test.cc)
  add_executable(delegation_demo_test delegation_demo_test.cc)
  target_link_libraries(delegation_demo_test delegation_demo_lib)
  proofs_add_testing_libraries(delegation_demo_test)
endif()

if(PROOFS_BUILD_TESTS)
  add_executable(delegation_crypto_smoke shared/delegation_crypto_smoke.cc)
  target_link_libraries(delegation_crypto_smoke delegation_demo_lib)
endif()
