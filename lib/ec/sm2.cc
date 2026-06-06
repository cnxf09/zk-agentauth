// Copyright 2026 Google LLC.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "ec/sm2.h"

namespace proofs {

const FpSM2Base sm2_base(
    FpSM2Nat("0xfffffffeffffffffffffffffffffffffffffffff00000000ffffffffffffffff"));

const FpSM2Nat nsm2_order(
    "0xfffffffeffffffffffffffffffffffff7203df6b21c6052b53bbf40939d54123");

const FpSM2Scalar sm2_scalar(nsm2_order);

const SM2 sm2(
    sm2_base.of_string(
        "0xfffffffeffffffffffffffffffffffffffffffff00000000fffffffffffffffc"),
    sm2_base.of_string(
        "0x28e9fa9e9d9f5e344d5a9e4bcf6509a7f39789f515ab8f92ddbcbd414d940e93"),
    sm2_base.of_string(
        "0x32c4ae2c1f1981195f9904466a39c9948fe30bbff2660be1715a4589334c74c7"),
    sm2_base.of_string(
        "0xbc3736a2f4f6779c59bdcee36b692153d0a9877cc62a474002df32e52139f0a0"),
    sm2_base);

}  // namespace proofs
