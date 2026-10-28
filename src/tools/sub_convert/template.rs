use std::borrow::Cow;

use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TemplateSource {
    Builtin,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TemplateDescriptor {
    pub id: &'static str,
    pub name: &'static str,
    pub description: &'static str,
    pub reference_key: &'static str,
    pub index: Option<usize>,
    pub source: TemplateSource,
    pub recommended: bool,
    pub sing_box_version: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedTemplate {
    pub descriptor: TemplateDescriptor,
    pub content_type: TemplateSource,
    pub reference_value: String,
    pub content: Cow<'static, str>,
}

pub fn builtin_templates() -> Vec<TemplateDescriptor> {
    [
        ("config_template_groups_rule_set_tun", "轻量代理（推荐）", "sing-box 1.14.x · HTTP / SOCKS 127.0.0.1:2080 · 自动测速与手动选择，无需管理员权限或远程规则。", "config_template_groups_rule_set_tun"),
        ("config_template_groups_rule_set_tun_fakeip", "TUN 全局代理 · FakeIP", "sing-box 1.14.x · 接管系统流量并启用 FakeIP，需要管理员权限；局域网直连。", "config_template_groups_rule_set_tun_fakeip"),
        ("config_template_no_groups_tun_vn", "TUN 全局代理 · 精简", "sing-box 1.14.x · 接管系统流量，手动选择节点，需要管理员权限；不启用 FakeIP。", "config_template_no_groups_tun_VN"),
        ("sb-config-1.12", "轻量代理 · 地区分组", "sing-box 1.14.x · 127.0.0.1:2080 · 按节点名称分组；空地区组回退到自动测速，不会静默直连。", "sb-config-1.12"),
        ("sb-config-1.14", "TUN 全局代理 · 地区分组", "sing-box 1.14.x · 接管系统流量、按地区选择节点，需要管理员权限；不依赖远程规则。", "sb-config-1.14"),
    ].into_iter().enumerate().map(|(index, (id, name, description, reference_key))| TemplateDescriptor {
        id, name, description, reference_key, index: Some(index + 1), source: TemplateSource::Builtin,
        recommended: index == 0, sing_box_version: "1.14.x",
    }).collect()
}

pub fn builtin_template_content(id: &str) -> Option<&'static str> {
    match id {
        "config_template_groups_rule_set_tun" => Some(include_str!(
            "templates/config_template_groups_rule_set_tun.json"
        )),
        "config_template_groups_rule_set_tun_fakeip" => Some(include_str!(
            "templates/config_template_groups_rule_set_tun_fakeip.json"
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
        .unwrap_or("1");
    if is_remote_template_value(requested) {
        return Err(
            "不再接受远程模板：为避免在服务器执行不可信配置，请使用经过校验的内置模板".to_string(),
        );
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
    .ok_or_else(|| format!("未知模板：{requested}，请重新选择内置模板"))?;
    let content = builtin_template_content(descriptor.id)
        .ok_or_else(|| format!("内置模板缺失：{}", descriptor.id))?;
    Ok(ResolvedTemplate {
        descriptor,
        content_type: TemplateSource::Builtin,
        reference_value: requested.to_string(),
        content: Cow::Borrowed(content),
    })
}

pub async fn load_template_text(template: &ResolvedTemplate) -> Result<String, String> {
    Ok(template.content.as_ref().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn templates_have_clear_version_and_one_recommendation() {
        let templates = builtin_templates();
        assert_eq!(templates.len(), 5);
        assert_eq!(
            templates
                .iter()
                .filter(|template| template.recommended)
                .count(),
            1
        );
        for descriptor in templates {
            assert_eq!(descriptor.sing_box_version, "1.14.x");
            assert!(descriptor.description.contains("1.14.x"));
            let by_index =
                resolve_template(None, Some(&descriptor.index.unwrap().to_string())).unwrap();
            assert_eq!(by_index.descriptor.id, descriptor.id);
            let by_name = resolve_template(Some(descriptor.reference_key), None).unwrap();
            assert_eq!(by_name.descriptor.id, descriptor.id);
            serde_json::from_str::<serde_json::Value>(by_name.content.as_ref()).unwrap();
        }
        let default = resolve_template(None, None).unwrap();
        let config: serde_json::Value = serde_json::from_str(default.content.as_ref()).unwrap();
        assert!(
            config["inbounds"]
                .as_array()
                .unwrap()
                .iter()
                .all(|inbound| inbound["type"] == "mixed")
        );
    }

    #[test]
    fn rejects_unknown_and_remote_templates() {
        assert!(
            resolve_template(None, Some("missing-template"))
                .unwrap_err()
                .contains("未知模板")
        );
        assert!(
            resolve_template(None, Some("https://example.com/template.json"))
                .unwrap_err()
                .contains("不再接受远程模板")
        );
    }
}
