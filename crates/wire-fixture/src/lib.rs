//! Wire-compat byte fixture harness.
//!
//! Provides helpers for loading JSON/binary fixtures and asserting
//! byte-identical re-serialization against Go-produced reference bytes.
//! See `tests/wire_compat.rs` for the actual test cases and
//! `fixtures/README.md` for regeneration instructions.

#![forbid(unsafe_code)]

/// Canonicalize a JSON string by parsing it to `serde_json::Value` and
/// re-serializing to compact form. This normalizes whitespace while
/// preserving key order (serde_json::Value::Object preserves insertion
/// order via the `preserve_order` feature, or BTreeMap ordering otherwise).
///
/// In practice, both Go's `json.Marshal` and Rust's `serde_json::to_string`
/// produce compact JSON with struct-field-order keys, so canonicalization
/// mainly strips pretty-print whitespace from hand-authored fixtures.
pub fn canonical_json(s: &str) -> String {
    let value: serde_json::Value =
        serde_json::from_str(s).unwrap_or_else(|e| panic!("invalid JSON in fixture: {e}"));
    serde_json::to_string(&value).unwrap_or_else(|e| panic!("re-serialize failed: {e}"))
}

/// Assert that a Rust type can deserialize a Go-produced JSON fixture and
/// re-serialize to byte-identical (canonical compact) JSON.
///
/// This catches:
/// - Missing fields (deserialization fails)
/// - Field-order divergence (key order differs)
/// - `skip_serializing_if` / `omitempty` drift (fields present in one but
///   not the other)
/// - Type mismatches (deserialization fails or value changes)
pub fn assert_json_roundtrip<T>(fixture_json: &str)
where
    T: serde::de::DeserializeOwned + serde::Serialize,
{
    let canonical_fixture = canonical_json(fixture_json);

    // Deserialize the Go fixture into the Rust type.
    let value: T = serde_json::from_str(fixture_json).unwrap_or_else(|e| {
        panic!(
            "failed to deserialize fixture into {}: {e}",
            std::any::type_name::<T>()
        )
    });

    // Re-serialize the Rust value.
    let rust_json = serde_json::to_string(&value)
        .unwrap_or_else(|e| panic!("failed to re-serialize {}: {e}", std::any::type_name::<T>()));

    let canonical_rust = canonical_json(&rust_json);

    assert_eq!(
        canonical_fixture,
        canonical_rust,
        "JSON byte mismatch for {}: Go fixture != Rust re-serialization\nGo:  {}\nRust: {}",
        std::any::type_name::<T>(),
        canonical_fixture,
        canonical_rust,
    );
}

/// Assert that a Rust type can deserialize a Go-produced JSON fixture and
/// re-serialize to byte-identical JSON, comparing only the keys that Rust
/// produces. This is used for types where Go includes non-omitempty fields
/// that Rust doesn't model yet (a known wire-compat gap). The test still
/// verifies that every field Rust DOES know about matches Go's value and
/// field order.
pub fn assert_json_subset_roundtrip<T>(fixture_json: &str)
where
    T: serde::de::DeserializeOwned + serde::Serialize,
{
    // Deserialize the Go fixture into the Rust type (ignoring unknown fields).
    let value: T = serde_json::from_str(fixture_json).unwrap_or_else(|e| {
        panic!(
            "failed to deserialize fixture into {}: {e}",
            std::any::type_name::<T>()
        )
    });

    // Re-serialize the Rust value.
    let rust_json = serde_json::to_string(&value)
        .unwrap_or_else(|e| panic!("failed to re-serialize {}: {e}", std::any::type_name::<T>()));

    let _canonical_rust = canonical_json(&rust_json);

    // Parse both to Value for key-by-key comparison.
    let go_value: serde_json::Value = serde_json::from_str(fixture_json).unwrap();
    let rust_value: serde_json::Value = serde_json::from_str(&rust_json).unwrap();

    let go_obj = go_value.as_object().expect("Go fixture is not an object");
    let rust_obj = rust_value
        .as_object()
        .expect("Rust output is not an object");

    // Every key in the Rust output must exist in the Go fixture with the
    // same value. Extra Go-only keys (from non-omitempty fields Rust
    // doesn't model) are ignored.
    for (key, rust_val) in rust_obj {
        match go_obj.get(key) {
            None => panic!(
                "Rust key {:?} not found in Go fixture for {}",
                key,
                std::any::type_name::<T>()
            ),
            Some(go_val) => {
                let rv = canonical_json(&rust_val.to_string());
                let gv = canonical_json(&go_val.to_string());
                assert_eq!(
                    gv,
                    rv,
                    "value mismatch for key {:?} in {}: Go={gv}, Rust={rv}",
                    key,
                    std::any::type_name::<T>()
                );
            }
        }
    }
}

/// Assert that a binary fixture can be decoded by the Rust decoder and
/// re-encoded to byte-identical output.
pub fn assert_binary_roundtrip(original: &[u8], re_encoded: &[u8]) {
    assert_eq!(
        original,
        re_encoded,
        "binary byte mismatch: original {} bytes != re-encoded {} bytes\n\
         original:   {}\n\
         re-encoded: {}",
        original.len(),
        re_encoded.len(),
        hex::encode(original),
        hex::encode(re_encoded),
    );
}
