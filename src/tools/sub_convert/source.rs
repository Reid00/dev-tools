use super::runtime::{sanitize_source, validate_subscription_url};

pub fn validate_subscription_input(url: &str) -> Result<String, String> {
    let url = sanitize_source(url)?;
    validate_subscription_url(&url)?;
    Ok(url)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_source_query_and_rejects_local_sources() {
        let url = "https://example.com/sub?token=a%2Bb%26c&file=source.json";
        assert_eq!(validate_subscription_input(url).unwrap(), url);
        assert!(validate_subscription_input("http://127.0.0.1/sub").is_err());
        assert!(validate_subscription_input("file:///etc/passwd").is_err());
    }
}
