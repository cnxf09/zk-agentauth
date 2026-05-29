# ZK-AgentAuth Ligero VP Token Profile v1

Profile URI: `https://zk-agentauth.local/profiles/vp-token/zkaa-ligero-v1`

This profile defines the demo-specific VP token shape used by TripGo when an
OpenID4VP `presentation_definition` asks for a ZK-AgentAuth Ligero proof.

## Format Identifier

- `format`: `zkaa+ligero`
- `proof_type`: `LigeroV2`
- `container`: ZIP encoded as base64 in `vp_token.presentation_zip_b64`
- `binding`: the proof is verified against the original reader request files
  generated for the matching `state` or `request_id`

## VP Token Object

```json
{
  "format": "zkaa+ligero",
  "profile": "https://zk-agentauth.local/profiles/vp-token/zkaa-ligero-v1",
  "presentation_zip_b64": "BASE64_ZIP",
  "claims": ["age_over_18"]
}
```

The `claims` array lists disclosed claim aliases that the prover intends to
satisfy for the current TripGo presentation definition. The verifier treats the
ZIP content as authoritative and still validates the proof with the native
`delegation_demo_verifier`.

## ZIP Members

Required files:

- `proof.bin`
- `public_delegation.json`
- `delegation_revocation_status.json`

Optional disclosed-claim files:

- `disclosed_claims_count.txt`
- `disclosed_alias_<i>.txt`
- `disclosed_namespace_<i>.txt`
- `disclosed_id_<i>.txt`
- `disclosed_cbor_value_<i>.bin`

The verifier must reject ZIP path traversal and must verify the extracted files
against the stored reader request directory for the same `state` or `request_id`.

## Presentation Definition Mapping

TripGo uses a single input descriptor:

```json
{
  "id": "zkaa-ligero-presentation",
  "format": {
    "zkaa+ligero": {
      "profile": "https://zk-agentauth.local/profiles/vp-token/zkaa-ligero-v1",
      "encoding": "application/zip;base64",
      "proof_type": "LigeroV2"
    }
  }
}
```

The wallet returns a non-empty `presentation_submission.descriptor_map`:

```json
{
  "id": "zkaa-ligero-presentation",
  "format": "zkaa+ligero",
  "path": "$.vp_token",
  "path_nested": {
    "format": "application/zip;base64",
    "path": "$.vp_token.presentation_zip_b64"
  }
}
```

## Request Binding

TripGo creates native request files with `delegation_demo_verifier request` and
stores them under the OID4VP request id. The outer OpenID4VP request object
carries:

- `state`
- `nonce`
- `response_mode=direct_post`
- `response_uri`
- `presentation_definition`
- `zkaa_request_id`

The request object is JWS signed by the TripGo verifier key advertised in
`/.well-known/oid4vp-verifier`. A wallet should prefer the signed
`request_object_jwt` when it wants to authenticate the verifier request.

## Verification Rules

1. Resolve the request metadata by `state` or `request_id`.
2. Reject if the metadata has already been consumed.
3. Validate `presentation_submission.definition_id` and descriptor map.
4. Decode and safely extract `vp_token.presentation_zip_b64`.
5. Run the native verifier against the stored reader request directory and the
   extracted presentation directory.
6. Mark the request metadata consumed immediately after verification.

## Security Notes

This profile is intentionally narrow. It is a ZK-AgentAuth interoperability
profile, not a general W3C Verifiable Presentation format. Production use should
add transport TLS, request-object validation by the wallet, verifier trust
configuration, clock-skew handling, and a durable replay cache.
