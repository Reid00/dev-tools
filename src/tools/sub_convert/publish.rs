pub fn build_config_path(subscription_url: &str, template: &str, user_agent: &str) -> String {
    let mut url = reqwest::Url::parse("http://localhost/api/sub/config").expect("static URL");
    url.query_pairs_mut()
        .append_pair("source", subscription_url)
        .append_pair("template", template)
        .append_pair("ua", user_agent);
    format!("{}?{}", url.path(), url.query().unwrap_or_default())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn publication_preserves_nested_query_and_encoded_credentials() {
        let source = "https://example.com/sub?token=a%2Bb%26c&file=source.json&x=你好";
        let path = build_config_path(source, "1", "clashmeta");
        let parsed = reqwest::Url::parse(&format!("http://localhost{path}")).unwrap();
        let values = parsed
            .query_pairs()
            .collect::<std::collections::HashMap<_, _>>();
        assert_eq!(values["source"], source);
        assert_eq!(values["template"], "1");
        assert_eq!(values["ua"], "clashmeta");
        assert!(!path.contains("你好"));
    }
}
