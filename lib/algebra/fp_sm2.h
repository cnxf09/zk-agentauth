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

#ifndef PRIVACY_PROOFS_ZK_LIB_ALGEBRA_FP_SM2_H_
#define PRIVACY_PROOFS_ZK_LIB_ALGEBRA_FP_SM2_H_

#include "algebra/fp.h"

namespace proofs {

// SM2P256V1 uses p = 0xfffffffeffffffffffffffffffffffffffffffff00000000ffffffffffffffff.
// The generic reducer is slower than the specialized P-256 reducer, but keeps
// the first SM2 circuit implementation small and auditable.
template <bool optimized_mul = false>
using FpSM2 = Fp<4, optimized_mul>;

}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_ALGEBRA_FP_SM2_H_
