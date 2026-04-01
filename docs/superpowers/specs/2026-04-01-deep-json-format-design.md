# Deep JSON Format Feature Design

## Summary

Add automatic detection and recursive formatting for nested JSON strings within JSON values. When a string field contains valid JSON, it will be parsed and formatted with smart indentation alignment relative to its parent structure.

## Motivation

API responses (like OpenAI chat completions) often return JSON objects where string fields contain escaped JSON strings. Example:

```json
{
  "choices": [{
    "message": {
      "content": "{\"classification\": {...}, \"extracted_info\": {...}}"
    }
  }]
}
```

Current `/format` endpoint treats `content` as a plain string, keeping the escaped JSON unreadable. This feature automatically detects and formats such nested JSON for better readability.

## Design

### Request Parameter

Add `max_depth: Option<usize>` to `FormatRequest`:

```rust
#[derive(Deserialize)]
pub struct FormatRequest {
    pub input: String,
    pub indent: Option<u32>,
    pub sort_keys: Option<bool>,
    pub max_depth: Option<usize>,  // NEW: recursion depth limit, default 3
}
```

- `max_depth = 0` or unset → no deep parsing (current behavior)
- `max_depth > 0` → parse string fields recursively up to this depth

### Core Algorithm

1. Parse input JSON as `Value`
2. If `max_depth` is set and > 0, call `deep_format_value(val, 0, max_depth, indent)`
3. For each string value encountered:
   - Attempt `serde_json::from_str::<Value>(&str)`
   - If successful and depth < max_depth: recursively format this nested JSON
   - If failed or depth >= max_depth: keep original string

### Smart Indentation Alignment

Nested JSON uses the same indent width as outer JSON, but its content is positioned relative to the field's location in the output.

**Example transformation:**

Input:
```json
{"message":{"content":"{\"a\":1,\"b\":2}"}}
```

Output (indent=2, max_depth=3):
```json
{
  "message": {
    "content": {
      "a": 1,
      "b": 2
    }
  }
}
```

The `content` field's value changes from escaped JSON string to a properly formatted JSON object, aligned with parent indentation.

### Implementation Details

```rust
fn deep_format_value(val: &Value, depth: usize, max_depth: usize, indent: usize) -> Value {
    if depth >= max_depth {
        return val.clone();
    }

    match val {
        Value::Object(map) => {
            let mut result = serde_json::Map::new();
            for (k, v) in map {
                result.insert(k.clone(), deep_format_value(v, depth + 1, max_depth, indent));
            }
            Value::Object(result)
        }
        Value::Array(arr) => {
            Value::Array(arr.iter().map(|v| deep_format_value(v, depth, max_depth, indent)).collect())
        }
        Value::String(s) => {
            // Try to parse as JSON
            if let Ok(nested) = serde_json::from_str::<Value>(s) {
                // Successfully parsed - recursively format
                deep_format_value(&nested, depth + 1, max_depth, indent)
            } else {
                // Not valid JSON - keep original
                val.clone()
            }
        }
        other => other.clone(),
    }
}
```

Note: Arrays do not increment depth (only nested structures count). Strings that parse as JSON increment depth.

### Output Format Challenge

The challenge is that serde_json's formatter will serialize a `Value::Object` as a regular JSON object (with newlines and indentation), not as an escaped string. This changes the semantic structure of the output.

Two approaches:

**Approach A: Transform Value tree, then serialize**

Convert nested JSON strings to `Value` objects in the tree. Output becomes semantically different (original escaped string becomes actual object), but is more readable.

**Approach B: Custom serializer**

Keep the string representation but format its content inline with proper indentation. This preserves semantic equivalence but requires custom serialization logic.

**Decision: Approach A**

The goal is readability for human inspection. Changing `"content": "{\"a\":1}"` to `"content": {"a": 1}` is acceptable for this use case. The user explicitly requested deep formatting, understanding the output structure will change.

### Edge Cases

1. **String containing non-JSON text** — Keep as-is, no modification
2. **String containing JSON primitive (number, bool, null)** — Parse and replace with actual primitive type
3. **Empty string or whitespace** — Keep as-is
4. **JSON with comments inside string** — Comments removed before parsing (reuse existing `remove_json_comments`)
5. **Depth limit reached** — Stop recursion, output formatted JSON at current level as string (escaped)

### Testing

Add unit tests for:

1. Simple nested JSON string → formatted object
2. Multiple levels of nesting → correct depth handling
3. `max_depth=1` → only one level parsed
4. Invalid JSON string → preserved unchanged
5. JSON primitive in string → converted to actual primitive
6. Mixed: some fields with nested JSON, some without
7. Array containing JSON strings → each element processed
8. Integration test via HTTP endpoint

## File Changes

- `src/tools/json_tools.rs`:
  - Add `max_depth` field to `FormatRequest`
  - Add `deep_format_value` function
  - Modify `format_json` handler to call deep formatting when `max_depth > 0`
  - Add tests for deep formatting

## API Example

```bash
curl -X POST http://localhost:3000/json/format \
  -H "Content-Type: application/json" \
  -d '{"input": "{\"content\": \"{\\\"a\\\": 1}\"}", "max_depth": 3}'
```

Response:
```json
{
  "result": "{\n  \"content\": {\n    \"a\": 1\n  }\n}",
  "valid": true,
  "stats": {...}
}
```