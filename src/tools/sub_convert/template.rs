use std::borrow::Cow;

use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TemplateSource {
    Builtin,
    Remote,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TemplateDescriptor {
    pub id: &'static str,
    pub name: &'static str,
    pub description: &'static str,
    pub reference_key: &'static str,
    pub index: Option<usize>,
    pub source: TemplateSource,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedTemplate {
    pub descriptor: TemplateDescriptor,
    pub content_type: TemplateSource,
    pub reference_value: String,
    pub content: Cow<'static, str>,
}

pub fn builtin_templates() -> Vec<TemplateDescriptor> {
    vec![
        TemplateDescriptor {
            id: "config_template_groups_rule_set_tun",
            name: "config_template_groups_rule_set_tun",
            description: "Builtin sing-box reference template.",
            reference_key: "config_template_groups_rule_set_tun",
            index: Some(1),
            source: TemplateSource::Builtin,
        },
        TemplateDescriptor {
            id: "config_template_groups_rule_set_tun_fakeip",
            name: "config_template_groups_rule_set_tun_fakeip",
            description: "Builtin sing-box reference template.",
            reference_key: "config_template_groups_rule_set_tun_fakeip",
            index: Some(2),
            source: TemplateSource::Builtin,
        },
        TemplateDescriptor {
            id: "config_template_no_groups_tun_vn",
            name: "config_template_no_groups_tun_vn",
            description: "Builtin sing-box reference template.",
            reference_key: "config_template_no_groups_tun_VN",
            index: Some(3),
            source: TemplateSource::Builtin,
        },
        TemplateDescriptor {
            id: "sb-config-1.12",
            name: "sb-config-1.12",
            description: "Builtin sing-box reference template.",
            reference_key: "sb-config-1.12",
            index: Some(4),
            source: TemplateSource::Builtin,
        },
        TemplateDescriptor {
            id: "sb-config-1.14",
            name: "sb-config-1.14",
            description: "Builtin sing-box reference template.",
            reference_key: "sb-config-1.14",
            index: Some(5),
            source: TemplateSource::Builtin,
        },
    ]
}

pub fn builtin_template_content(id: &str) -> Option<&'static str> {
    match id {
        "config_template_groups_rule_set_tun" => Some(include_str!(
            "templates/config_template_groups_rule_set_tun.json"
        )),
        "config_template_groups_rule_set_tun_fakeip" => Some(include_str!(
            "templates/config_template_groups_rule_set_tun_fakeip.json",
        )),
        "config_template_no_groups_tun_vn" => Some(include_str!(
            "templates/config_template_no_groups_tun_VN.json"
        )),
        "sb-config-1.12" => Some(include_str!("templates/sb-config-1.12.json")),
        "sb-config-1.14" => Some(include_str!("templates/sb-config-1.14.json")),
        _ => None,
    }
}

pub fn is_remote_template_value(value: &str) -> bool {
    reqwest::Url::parse(value)
        .map(|url| matches!(url.scheme(), "http" | "https"))
        .unwrap_or(false)
}

pub fn resolve_template(
    template: Option<&str>,
    file: Option<&str>,
) -> Result<ResolvedTemplate, String> {
    let requested = template
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .or_else(|| file.map(str::trim).filter(|value| !value.is_empty()))
        .unwrap_or("sb-config-1.14");

    if is_remote_template_value(requested) {
        return Ok(ResolvedTemplate {
            descriptor: TemplateDescriptor {
                id: "remote-template",
                name: "Remote Template",
                description: "Remote JSON template referenced by URL.",
                reference_key: "file",
                index: None,
                source: TemplateSource::Remote,
            },
            content_type: TemplateSource::Remote,
            reference_value: requested.to_string(),
            content: Cow::Owned(String::new()),
        });
    }

    let descriptor = if let Ok(index) = requested.parse::<usize>() {
        builtin_templates()
            .into_iter()
            .find(|template| template.index == Some(index))
    } else {
        builtin_templates().into_iter().find(|template| {
            template.id.eq_ignore_ascii_case(requested) || template.reference_key == requested
        })
    }
    .ok_or_else(|| format!("Unknown template: {requested}"))?;

    let content = builtin_template_content(descriptor.id)
        .ok_or_else(|| format!("Missing builtin template content for {}", descriptor.id))?;

    Ok(ResolvedTemplate {
        descriptor,
        content_type: TemplateSource::Builtin,
        reference_value: requested.to_string(),
        content: Cow::Borrowed(content),
    })
}

pub async fn load_template_text(template: &ResolvedTemplate) -> Result<String, String> {
    match template.content_type {
        TemplateSource::Builtin => Ok(template.content.as_ref().to_string()),
        TemplateSource::Remote => {
            super::runtime::fetch_remote_text(
                &template.reference_value,
                "sing-box-template/1.0",
                "remote template",
                512 * 1024,
            )
            .await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_templates_are_sorted_and_expose_reference_keys() {
        let templates = builtin_templates();
        let ids = templates
            .iter()
            .map(|template| template.id)
            .collect::<Vec<_>>();

        assert_eq!(
            ids,
            vec![
                "config_template_groups_rule_set_tun",
                "config_template_groups_rule_set_tun_fakeip",
                "config_template_no_groups_tun_vn",
                "sb-config-1.12",
                "sb-config-1.14",
            ]
        );
        assert_eq!(
            templates[0].reference_key,
            "config_template_groups_rule_set_tun"
        );
        assert_eq!(templates[0].index, Some(1));
        assert_eq!(templates[4].reference_key, "sb-config-1.14");
        assert_eq!(templates[4].index, Some(5));
    }

    #[test]
    fn resolve_template_accepts_builtin_id_and_reference_key() {
        let by_id = resolve_template(Some("sb-config-1.14"), Some("sb-config-1.14")).unwrap();
        assert_eq!(by_id.descriptor.id, "sb-config-1.14");
        assert_eq!(by_id.content_type, TemplateSource::Builtin);

        let by_reference =
            resolve_template(None, Some("config_template_no_groups_tun_VN")).unwrap();
        assert_eq!(
            by_reference.descriptor.id,
            "config_template_no_groups_tun_vn"
        );
    }

    #[test]
    fn resolve_template_accepts_numeric_file_index() {
        let resolved = resolve_template(None, Some("5")).unwrap();
        assert_eq!(resolved.descriptor.id, "sb-config-1.14");
    }

    #[test]
    fn resolve_template_marks_remote_template_urls() {
        let resolved = resolve_template(None, Some("https://example.com/template.json")).unwrap();
        assert_eq!(resolved.descriptor.id, "remote-template");
        assert_eq!(resolved.content_type, TemplateSource::Remote);
        assert_eq!(
            resolved.reference_value,
            "https://example.com/template.json"
        );
    }

    #[test]
    fn resolve_template_rejects_unknown_values() {
        let err = resolve_template(None, Some("missing-template")).unwrap_err();
        assert_eq!(err, "Unknown template: missing-template");
    }

    #[tokio::test]
    async fn load_template_text_rejects_private_remote_template_urls() {
        let resolved = resolve_template(None, Some("http://127.0.0.1/template.json")).unwrap();

        let err = load_template_text(&resolved).await.unwrap_err();

        assert!(err.contains("Private IP"));
    }
}
