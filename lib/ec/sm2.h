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

#ifndef PRIVACY_PROOFS_ZK_LIB_EC_SM2_H_
#define PRIVACY_PROOFS_ZK_LIB_EC_SM2_H_

#include "algebra/fp.h"
#include "algebra/fp_sm2.h"
#include "ec/elliptic_curve.h"

namespace proofs {

using FpSM2Base = FpSM2<false>;
using FpSM2Scalar = Fp<4, false>;
using FpSM2Nat = FpSM2Base::N;

extern const FpSM2Base sm2_base;
extern const FpSM2Nat nsm2_order;
extern const FpSM2Scalar sm2_scalar;

typedef EllipticCurve<FpSM2Base, 4, 256> SM2;

extern const SM2 sm2;

}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_EC_SM2_H_
