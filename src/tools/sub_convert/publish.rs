pub fn build_config_path(subscription_url: &str, reference_value: &str) -> String {
    format!(
        "/api/sub/config/{}&file={}",
        subscription_url.trim(),
        reference_value.trim()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_config_path_uses_reference_value() {
        let path = build_config_path("https://example.com/sub?token=abc", "sb-config-1.14");

        assert_eq!(
            path,
            "/api/sub/config/https://example.com/sub?token=abc&file=sb-config-1.14"
        );
    }
}
