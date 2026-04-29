//! 沙箱全局注册表。
//!
//! 职责：记录 SDK 进程内仍然存活的 `Sandbox` 实例元信息。
//! 边界：只维护 SDK 侧生命周期状态，不持有或操作任何后端资源。

use crate::config::IsolationLevel;
use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};
use std::time::Instant;
use uuid::Uuid;

static SANDBOX_REGISTRY: LazyLock<Mutex<HashMap<Uuid, SandboxInfo>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// SDK 沙箱实例的注册表快照。
#[derive(Debug, Clone)]
pub struct SandboxInfo {
    /// SDK 沙箱实例的全局唯一 ID。
    pub id: Uuid,
    /// 用户配置的隔离级别；初始化前可能尚未写入。
    pub configured_isolation: Option<IsolationLevel>,
    /// 当前实际启用的隔离级别；后端未初始化时为 `None`。
    pub active_isolation: Option<IsolationLevel>,
    /// 注册表创建该条目的时间。
    pub created_at: Instant,
    /// 当前后端是否已经进入可用状态。
    pub is_ready: bool,
}

/// 注册一个新的 SDK 沙箱实例，并返回它的全局 ID。
pub fn register() -> Uuid {
    let id = Uuid::new_v4();
    let info = SandboxInfo {
        id,
        configured_isolation: None,
        active_isolation: None,
        created_at: Instant::now(),
        is_ready: false,
    };

    registry_entries().insert(id, info);
    id
}

/// 从全局注册表移除指定沙箱实例。
pub fn unregister(id: Uuid) {
    registry_entries().remove(&id);
}

/// 更新指定沙箱实例的配置隔离级别和实际隔离级别。
pub fn update_isolation(
    id: Uuid,
    configured: Option<IsolationLevel>,
    active: Option<IsolationLevel>,
) {
    if let Some(info) = registry_entries().get_mut(&id) {
        info.configured_isolation = configured;
        info.active_isolation = active;
    }
}

/// 更新指定沙箱实例的就绪状态。
pub fn update_ready(id: Uuid, ready: bool) {
    if let Some(info) = registry_entries().get_mut(&id) {
        info.is_ready = ready;
    }
}

/// 返回当前所有已注册沙箱实例的快照。
pub fn list() -> Vec<SandboxInfo> {
    registry_entries().values().cloned().collect()
}

/// 返回指定沙箱实例的注册表快照。
pub fn get(id: Uuid) -> Option<SandboxInfo> {
    registry_entries().get(&id).cloned()
}

fn registry_entries() -> std::sync::MutexGuard<'static, HashMap<Uuid, SandboxInfo>> {
    SANDBOX_REGISTRY.lock().unwrap_or_else(|e| e.into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_register_and_list() {
        let id = register();

        let sandboxes = list();

        assert!(sandboxes.iter().any(|sandbox| sandbox.id == id));
        unregister(id);
    }

    #[test]
    fn test_unregister() {
        let id = register();

        unregister(id);

        assert!(get(id).is_none());
    }

    #[test]
    fn test_update_isolation() {
        let id = register();

        update_isolation(id, Some(IsolationLevel::Auto), Some(IsolationLevel::Os));
        let Some(info) = get(id) else {
            unregister(id);
            panic!("registered sandbox info should exist");
        };

        assert_eq!(info.configured_isolation, Some(IsolationLevel::Auto));
        assert_eq!(info.active_isolation, Some(IsolationLevel::Os));
        unregister(id);
    }

    #[test]
    fn test_update_ready() {
        let id = register();

        update_ready(id, true);
        let Some(info) = get(id) else {
            unregister(id);
            panic!("registered sandbox info should exist");
        };

        assert!(info.is_ready);
        unregister(id);
    }

    #[test]
    fn test_get_nonexistent() {
        assert!(get(Uuid::new_v4()).is_none());
    }
}
