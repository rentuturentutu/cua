use super::*;
use crate::uia::UiaNode;

fn node(actions: Vec<String>) -> UiaNode {
    UiaNode {
        element_index: Some(1),
        control_type: "Button".to_owned(),
        name: Some("OK".to_owned()),
        value: None,
        automation_id: None,
        help_text: None,
        actions,
        enabled: Some(true),
        selected: None,
        element_ptr: 0,
        owns_element_ptr: false,
        center_x: 0,
        center_y: 0,
        rect: None,
        msaa_role: None,
        depth: 0,
        parent_element_index: None,
        in_web_content: false,
    }
}

#[test]
fn element_entry_includes_actions_when_present() {
    let n = node(vec!["invoke".to_owned(), "toggle".to_owned()]);
    let entry = build_element_entry(&n, None).unwrap();
    assert_eq!(entry["actions"], json!(["invoke", "toggle"]));
}

#[test]
fn element_entry_omits_actions_when_empty() {
    let n = node(Vec::new());
    let entry = build_element_entry(&n, None).unwrap();
    assert!(entry.get("actions").is_none());
}

#[test]
fn element_entry_distinguishes_native_and_web_documents() {
    let mut native = node(Vec::new());
    native.control_type = "Document".to_owned();
    let native_entry = build_element_entry(&native, None).unwrap();
    assert_eq!(native_entry["in_web_content"], json!(false));

    let mut web = native;
    web.in_web_content = true;
    let web_entry = build_element_entry(&web, None).unwrap();
    assert_eq!(web_entry["in_web_content"], json!(true));
}
