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

#ifndef PRIVACY_PROOFS_ZK_LIB_ALGEBRA_BOGORNG_H_
#define PRIVACY_PROOFS_ZK_LIB_ALGEBRA_BOGORNG_H_

namespace proofs {
// Totally bogus "random" number generator, used only for testing.
// There is no guarantee that it will cycle over all elements in the
// field, but this keeps dependencies internal to this directory.
// The public and internal functions of this class all take a const Field&
// parameter to produce random elements in the Field. It is the caller's
// responsibility to ensure the object remains valid during execution.
template <class Field>
class Bogorng {
  using Elt = typename Field::Elt;

 public:
  explicit Bogorng(const Field* F)
      : f_(F), next_(F->of_scalar_field(123456789u)) {}

  Elt next() {
    // really old-school
    f_->mul(next_, f_->of_scalar_field(1103515245u));
    f_->add(next_, f_->of_scalar_field(12345u));
    return next_;
  }

  Elt nonzero() {
    Elt x;
    do {
      x = next();
    } while (x == f_->zero());
    return x;
  }

 private:
  const Field* f_;
  Elt next_;
};
}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_ALGEBRA_BOGORNG_H_
