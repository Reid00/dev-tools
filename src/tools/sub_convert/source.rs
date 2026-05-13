use super::runtime::{sanitize_source, validate_subscription_url};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedConfigSource {
    pub subscription_url: String,
    pub file: Option<String>,
}

pub fn validate_subscription_input(url: &str) -> Result<String, String> {
    let url = sanitize_source(url)?;
    validate_subscription_url(&url)?;
    Ok(url)
}

pub fn split_config_source_and_query(raw: &str) -> Result<ParsedConfigSource, String> {
    let value = sanitize_source(raw)?;
    let marker = "&file=";

    let (subscription_url, file) = if let Some(index) = value.rfind(marker) {
        let subscription_url = value[..index].to_string();
        let file = value[index + marker.len()..].trim().to_string();
        let file = if file.is_empty() { None } else { Some(file) };
        (subscription_url, file)
    } else {
        (value.clone(), None)
    };

    validate_subscription_url(&subscription_url)?;

    Ok(ParsedConfigSource {
        subscription_url,
        file,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_config_source_keeps_inner_query_and_extracts_file_param() {
        let parsed =
            split_config_source_and_query("https://example.com/sub?token=abc&file=sb-config-1.14")
                .unwrap();

        assert_eq!(parsed.subscription_url, "https://example.com/sub?token=abc");
        assert_eq!(parsed.file.as_deref(), Some("sb-config-1.14"));
    }

    #[test]
    fn split_config_source_supports_pipe_free_remote_template() {
        let parsed = split_config_source_and_query(
            "https://example.com/sub?token=abc&file=https://remote.test/template.json",
        )
        .unwrap();

        assert_eq!(
            parsed.file.as_deref(),
            Some("https://remote.test/template.json")
        );
    }
}
