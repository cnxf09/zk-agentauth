# MDOC Anonymous Credential Demo

This demo keeps the local file-based CLI flow from `examples/anoncred`, but it
switches the credential input from the toy `small` format to real `DeviceResponse`
examples from `lib/circuits/mdoc/mdoc_examples.h`.

Current scope:

- no transport changes
- local files only
- prover/verifier reuse `run_mdoc_prover` / `run_mdoc_verifier`
- request semantics use real `RequestedAttribute` claims
- verifier request generates a fresh OpenID4VP `SessionTranscript`
- holder dynamically signs the fresh transcript on every `prove`
- `issuer issue` rewrites the sample template with a fresh issuer key and fresh
  holder device key
- `issuer issue-custom` interactively builds a minimal real mdoc with:
  - `family_name`
  - `given_name`
  - `birth_date`
  - `issue_date`
  - `expiry_date`
  - `issuing_country`
  - `age_over_18`
- request directory now contains encoded request artifacts:
  - `reader_request.cbor`
  - `session_transcript.cbor`
  - `openid4vp_request.json`

Commands:

```bash
./build-demo-cli/examples/mdoc_anoncred/mdoc_anoncred_console guided --out-root run/mdoc-interactive

./build-demo-cli/examples/mdoc_anoncred/mdoc_anoncred_issuer issue --example 3 --out run/mdoc-demo/issue
./build-demo-cli/examples/mdoc_anoncred/mdoc_anoncred_verifier request --issuer-public run/mdoc-demo/issue/issuer_public --claim age_over_18 --out run/mdoc-demo/request
./build-demo-cli/examples/mdoc_anoncred/mdoc_anoncred_holder prove --holder run/mdoc-demo/issue/holder --issuer-public run/mdoc-demo/issue/issuer_public --request run/mdoc-demo/request --out run/mdoc-demo/presentation
./build-demo-cli/examples/mdoc_anoncred/mdoc_anoncred_verifier verify --issuer-public run/mdoc-demo/issue/issuer_public --request run/mdoc-demo/request --presentation run/mdoc-demo/presentation

printf 'Researcher\nAlice\n1999-12-31\n2024-01-01\n2030-01-01\nUS\ntrue\n' | \
  ./build-demo-cli/examples/mdoc_anoncred/mdoc_anoncred_issuer issue-custom --out run/mdoc-custom/issue
./build-demo-cli/examples/mdoc_anoncred/mdoc_anoncred_verifier request --issuer-public run/mdoc-custom/issue/issuer_public --claim given_name --claim issuing_country --out run/mdoc-custom/request
./build-demo-cli/examples/mdoc_anoncred/mdoc_anoncred_holder prove --holder run/mdoc-custom/issue/holder --issuer-public run/mdoc-custom/issue/issuer_public --request run/mdoc-custom/request --out run/mdoc-custom/presentation
./build-demo-cli/examples/mdoc_anoncred/mdoc_anoncred_verifier verify --issuer-public run/mdoc-custom/issue/issuer_public --request run/mdoc-custom/request --presentation run/mdoc-custom/presentation
```

Interactive mode:

- `mdoc_anoncred_console guided` now supports two modes:
  - sample-based issuance
  - custom interactive issuance
- `mdoc_anoncred_issuer issue` prompts for example selection if `--example` is omitted
- `mdoc_anoncred_issuer issue-custom` prompts for custom field values
- `mdoc_anoncred_verifier request` prompts for claim selection if `--claim` is omitted

Supported claim aliases:

- `age_over_18`
- `family_name_mustermann`
- `birth_date_1971_09_01`
- `height_175`
- `family_name` via `issue-custom`
- `given_name` via `issue-custom`
- `birth_date` via `issue-custom`
- `issue_date` via `issue-custom`
- `expiry_date` via `issue-custom`
- `issuing_country` via `issue-custom`
