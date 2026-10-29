use super::UiaNode;
use cua_driver_core::snapshot_store::{SnapshotPayload, SnapshotStore};
use windows::core::Interface;
use windows::Win32::UI::Accessibility::{IAccessible, IUIAutomationElement};

pub type Snapshots = SnapshotStore<UiaSnapshot>;

#[derive(Debug)]
pub struct RetainedElement {
    ptr: usize,
    pub kind: SnapshotKind,
    pub center: (i32, i32),
    pub rect: Option<(i32, i32, i32, i32)>,
    pub msaa_role: Option<i32>,
}

impl RetainedElement {
    pub fn as_ptr(&self) -> usize {
        self.ptr
    }

    pub fn is_uia(&self) -> bool {
        self.kind == SnapshotKind::Uia
    }

    pub fn focus_element(&self) -> anyhow::Result<()> {
        if !self.is_uia() {
            anyhow::bail!("element is an MSAA element, not a UIA element");
        }
        let element = unsafe { IUIAutomationElement::from_raw(self.ptr as *mut _) };
        let result = unsafe { element.SetFocus() };
        std::mem::forget(element);
        result.map_err(|e| anyhow::anyhow!("UIA SetFocus failed: {e}"))
    }

    pub fn element_has_keyboard_focus(&self) -> Option<bool> {
        if !self.is_uia() {
            return None;
        }
        let element = unsafe { IUIAutomationElement::from_raw(self.ptr as *mut _) };
        let focused = unsafe { element.CurrentHasKeyboardFocus() }
            .ok()
            .map(|value| value.as_bool());
        std::mem::forget(element);
        focused
    }
}

impl Clone for RetainedElement {
    fn clone(&self) -> Self {
        if self.ptr != 0 {
            unsafe {
                match self.kind {
                    SnapshotKind::Uia => {
                        let iface = IUIAutomationElement::from_raw(self.ptr as *mut _);
                        let dup = iface.clone();
                        std::mem::forget(iface);
                        std::mem::forget(dup);
                    }
                    SnapshotKind::Msaa => {
                        let iface = IAccessible::from_raw(self.ptr as *mut _);
                        let dup = iface.clone();
                        std::mem::forget(iface);
                        std::mem::forget(dup);
                    }
                }
            }
        }
        Self {
            ptr: self.ptr,
            kind: self.kind,
            center: self.center,
            rect: self.rect,
            msaa_role: self.msaa_role,
        }
    }
}

impl Drop for RetainedElement {
    fn drop(&mut self) {
        if self.ptr != 0 {
            unsafe {
                match self.kind {
                    SnapshotKind::Uia => drop(IUIAutomationElement::from_raw(self.ptr as *mut _)),
                    SnapshotKind::Msaa => drop(IAccessible::from_raw(self.ptr as *mut _)),
                }
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnapshotKind {
    Uia,
    Msaa,
}

pub struct UiaSnapshot {
    elements: Vec<RetainedElement>,
}

impl UiaSnapshot {
    pub fn from_nodes(nodes: &[UiaNode], kind: SnapshotKind) -> Self {
        Self {
            elements: nodes
                .iter()
                .filter(|node| node.element_index.is_some() && node.owns_element_ptr)
                .map(|node| {
                    retain_raw(node.element_ptr, kind);
                    RetainedElement {
                        ptr: node.element_ptr,
                        kind,
                        center: (node.center_x, node.center_y),
                        rect: node.rect,
                        msaa_role: node.msaa_role,
                    }
                })
                .collect(),
        }
    }
}

fn retain_raw(ptr: usize, kind: SnapshotKind) {
    if ptr == 0 {
        return;
    }
    unsafe {
        match kind {
            SnapshotKind::Uia => {
                let element = IUIAutomationElement::from_raw(ptr as *mut _);
                let duplicate = element.clone();
                std::mem::forget(element);
                std::mem::forget(duplicate);
            }
            SnapshotKind::Msaa => {
                let element = IAccessible::from_raw(ptr as *mut _);
                let duplicate = element.clone();
                std::mem::forget(element);
                std::mem::forget(duplicate);
            }
        }
    }
}

impl SnapshotPayload for UiaSnapshot {
    type Element = RetainedElement;

    fn len(&self) -> usize {
        self.elements.len()
    }

    fn retain(&self, index: usize) -> Option<Self::Element> {
        self.elements
            .get(index)
            .filter(|element| element.ptr != 0)
            .cloned()
    }
}

#[cfg(test)]
#[path = "snapshot_uaf_repro.rs"]
mod snapshot_uaf_repro;
