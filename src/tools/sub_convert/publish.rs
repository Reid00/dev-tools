#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReferenceQueryParams {
    pub ua: String,
    pub emoji: String,
    pub eps: String,
}

impl Default for ReferenceQueryParams {
    fn default() -> Self {
        Self {
            ua: "clashmeta".to_string(),
            emoji: "1".to_string(),
            eps: "ssr".to_string(),
        }
    }
}

impl ReferenceQueryParams {
    pub fn new(ua: Option<&str>, emoji: Option<&str>, eps: Option<&str>) -> Self {
        let default = Self::default();
        Self {
            ua: value_or_default(ua, default.ua),
            emoji: value_or_default(emoji, default.emoji),
            eps: value_or_default(eps, default.eps),
        }
    }

    fn pairs(&self) -> [(&str, &str); 3] {
        [("ua", &self.ua), ("emoji", &self.emoji), ("eps", &self.eps)]
    }
}

pub fn append_reference_query_params(
    subscription_url: &str,
    params: &ReferenceQueryParams,
) -> String {
    let mut url = subscription_url.trim().to_string();

    for (key, value) in params.pairs() {
        if !has_query_param(&url, key) {
            let separator = if url.contains('?') { '&' } else { '?' };
            url.push(separator);
            url.push_str(key);
            url.push('=');
            url.push_str(value);
        }
    }

    url
}

pub fn build_config_path(
    subscription_url: &str,
    file_value: &str,
    params: &ReferenceQueryParams,
) -> String {
    format!(
        "/api/sub/config/{}&file={}",
        append_reference_query_params(subscription_url, params),
        file_value.trim()
    )
}

fn value_or_default(value: Option<&str>, default: String) -> String {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
        .unwrap_or(default)
}

fn has_query_param(url: &str, key: &str) -> bool {
    let Some((_, query)) = url.split_once('?') else {
        return false;
    };
    let query = query.split('#').next().unwrap_or(query);

    query.split('&').any(|pair| {
        pair.split_once('=')
            .map(|(name, _)| name == key)
            .unwrap_or(pair == key)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_config_path_appends_reference_params_and_file() {
        let params = ReferenceQueryParams::default();
        let path = build_config_path("https://example.com/sub?token=abc", "5", &params);

        assert_eq!(
            path,
            "/api/sub/config/https://example.com/sub?token=abc&ua=clashmeta&emoji=1&eps=ssr&file=5"
        );
    }

    #[test]
    fn append_reference_query_params_preserves_existing_values() {
        let params = ReferenceQueryParams::default();
        let url =
            append_reference_query_params("https://example.com/sub?ua=custom&token=abc", &params);

        assert_eq!(
            url,
            "https://example.com/sub?ua=custom&token=abc&emoji=1&eps=ssr"
        );
    }

    #[test]
    fn reference_query_params_use_custom_non_empty_values() {
        let params = ReferenceQueryParams::new(Some("surge"), Some("0"), Some("vless"));
        let url = append_reference_query_params("https://example.com/sub", &params);

        assert_eq!(url, "https://example.com/sub?ua=surge&emoji=0&eps=vless");
    }

    #[test]
    fn reference_query_params_fall_back_for_empty_values() {
        let params = ReferenceQueryParams::new(Some(" "), Some("0"), None);
        let url = append_reference_query_params("https://example.com/sub", &params);

        assert_eq!(url, "https://example.com/sub?ua=clashmeta&emoji=0&eps=ssr");
    }
}
