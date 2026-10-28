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
        ("config_template_groups_rule_set_tun", "国内直连 · 国外代理（推荐）", "sing-box 1.14.x · Android 授予 VPN 权限后自动接入，无需逐个设置应用代理；桌面使用 TUN 需管理员权限。按规则将国内域名/IP、局域网直连，其余走代理，DNS 配套分流；仅保留自动测速和手动选节点，无地区分组或 FakeIP。首次启动需通过可用代理下载两份国内规则，之后缓存并自动更新；启动失败请查看规则下载或节点连接错误。", "config_template_groups_rule_set_tun"),
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
    }

    #[test]
    fn default_template_uses_tun_with_domestic_direct_and_foreign_proxy() {
        let template = resolve_template(None, None).unwrap();
        assert_eq!(template.descriptor.index, Some(1));
        assert!(
            template
                .descriptor
                .description
                .contains("Android 授予 VPN 权限")
        );
        assert!(template.descriptor.description.contains("国内域名/IP"));
        let config: serde_json::Value = serde_json::from_str(template.content.as_ref()).unwrap();
        let inbounds = config["inbounds"].as_array().unwrap();
        assert_eq!(inbounds.len(), 2);
        let tun = &inbounds[0];
        assert_eq!(tun["type"], "tun");
        assert_eq!(tun["auto_route"], true);
        assert_eq!(tun["stack"], "system");
        assert_eq!(
            tun["address"],
            serde_json::json!(["172.19.0.1/30", "fdfe:dcba:9876::1/126"])
        );
        let mixed = &inbounds[1];
        assert_eq!(mixed["type"], "mixed");
        assert_eq!(mixed["listen"], "127.0.0.1");
        assert_eq!(mixed["listen_port"], 2080);
        assert!(mixed.get("set_system_proxy").is_none());
        assert_eq!(config["route"]["final"], "Proxy");
        assert_eq!(config["route"]["auto_detect_interface"], true);
        assert_eq!(
            config["route"]["rules"],
            serde_json::json!([
                {"action":"sniff"},
                {"type":"logical","mode":"or","rules":[{"protocol":"dns"},{"port":53}],"action":"hijack-dns"},
                {"ip_is_private":true,"action":"route","outbound":"direct"},
                {"rule_set":["geosite-cn"],"action":"route","outbound":"direct"},
                {"action":"resolve"},
                {"rule_set":["geoip-cn"],"action":"route","outbound":"direct"},
                {"ip_is_private":true,"action":"route","outbound":"direct"}
            ])
        );
        let outbounds = config["outbounds"].as_array().unwrap();
        assert_eq!(outbounds.len(), 3);
        assert_eq!(outbounds[0]["type"], "selector");
        assert_eq!(outbounds[0]["default"], "auto");
        assert_eq!(outbounds[1]["type"], "urltest");
        assert_eq!(outbounds[2]["type"], "direct");
        assert!(
            outbounds
                .iter()
                .all(|outbound| outbound.get("filter").is_none())
        );
    }

    #[test]
    fn default_template_splits_dns_without_proxy_bootstrap_loop() {
        let template = resolve_template(None, None).unwrap();
        let config: serde_json::Value = serde_json::from_str(template.content.as_ref()).unwrap();
        assert_eq!(
            config["dns"]["rules"],
            serde_json::json!([{"rule_set":["geosite-cn"],"action":"route","server":"local"}])
        );
        assert_eq!(config["dns"]["final"], "remote");
        assert_eq!(config["dns"]["reverse_mapping"], true);
        assert_eq!(config["route"]["default_domain_resolver"], "local");
        let servers = config["dns"]["servers"].as_array().unwrap();
        assert_eq!(servers.len(), 2);
        let local = servers
            .iter()
            .find(|server| server["tag"] == "local")
            .unwrap();
        assert_eq!(local["type"], "udp");
        assert_eq!(local["detour"], "direct");
        assert!(
            local["server"]
                .as_str()
                .unwrap()
                .parse::<std::net::IpAddr>()
                .is_ok()
        );
        let remote = servers
            .iter()
            .find(|server| server["tag"] == "remote")
            .unwrap();
        assert_eq!(remote["type"], "https");
        assert_eq!(remote["detour"], "Proxy");
        assert_eq!(remote["path"], "/dns-query");
        assert!(
            remote["server"]
                .as_str()
                .unwrap()
                .parse::<std::net::IpAddr>()
                .is_ok()
        );
        assert!(remote.get("tls").is_none());
        assert!(servers.iter().all(|server| server["type"] != "fakeip"));
        let source = "trojan://secret@example.com:443#Good";
        let nodes = super::super::parser::parse_subscription_content(source).unwrap();
        let rendered =
            super::super::render::render_template(template.content.as_ref(), &nodes).unwrap();
        super::super::validate::validate_references(&rendered).unwrap();
        assert_eq!(
            rendered["outbounds"][1]["outbounds"],
            serde_json::json!(["Good"])
        );
        for key in ["dns", "http_clients", "route", "inbounds", "experimental"] {
            assert_eq!(rendered[key], config[key]);
        }
    }

    #[test]
    fn default_template_bootstraps_and_caches_only_two_domestic_rule_sets() {
        let template = resolve_template(None, None).unwrap();
        let config: serde_json::Value = serde_json::from_str(template.content.as_ref()).unwrap();
        assert!(template.descriptor.description.contains("首次启动"));
        assert!(template.descriptor.description.contains("规则下载"));
        assert_eq!(
            config["http_clients"],
            serde_json::json!([{"tag":"rule-download","detour":"Proxy"}])
        );
        assert_eq!(config["route"]["default_http_client"], "rule-download");
        let rule_sets = config["route"]["rule_set"].as_array().unwrap();
        assert_eq!(rule_sets.len(), 2);
        assert_eq!(rule_sets[0]["tag"], "geosite-cn");
        assert_eq!(rule_sets[1]["tag"], "geoip-cn");
        for rule_set in rule_sets {
            assert_eq!(rule_set["type"], "remote");
            assert_eq!(rule_set["format"], "binary");
            assert_eq!(rule_set["http_client"], "rule-download");
            assert_eq!(rule_set["update_interval"], "1d");
            let url = reqwest::Url::parse(rule_set["url"].as_str().unwrap()).unwrap();
            assert_eq!(url.scheme(), "https");
            assert_eq!(url.host_str(), Some("raw.githubusercontent.com"));
            assert!(
                url.path()
                    .ends_with(&format!("/{}.srs", rule_set["tag"].as_str().unwrap()))
            );
            assert!(rule_set.get("download_detour").is_none());
        }
        assert_eq!(
            config["experimental"],
            serde_json::json!({"cache_file":{"enabled":true}})
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
