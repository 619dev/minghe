//! SIP 事务管理模块
//!
//! 简化的 SIP 事务层，跟踪活跃事务状态。

use std::collections::HashMap;
use std::sync::RwLock;
use std::time::Instant;

/// 事务状态
#[derive(Debug, Clone, PartialEq)]
pub enum TransactionState {
    /// 处理中（已收到请求，等待最终响应）
    Proceeding,
    /// 已完成（已收到最终响应）
    Completed,
    /// 已终止
    Terminated,
}

/// 事务信息
#[derive(Debug, Clone)]
pub struct Transaction {
    /// Via 分支参数（事务唯一标识）
    pub branch: String,
    /// SIP 方法
    pub method: String,
    /// Call-ID
    pub call_id: String,
    /// 创建时间
    pub created_at: Instant,
    /// 事务状态
    pub state: TransactionState,
}

/// 事务管理器
///
/// 跟踪所有活跃的 SIP 事务，提供创建、查询、更新和清理功能。
pub struct TransactionManager {
    transactions: RwLock<HashMap<String, Transaction>>,
}

impl TransactionManager {
    /// 创建新的事务管理器
    pub fn new() -> Self {
        Self {
            transactions: RwLock::new(HashMap::new()),
        }
    }

    /// 创建新事务
    ///
    /// # 参数
    /// - `branch`: Via 分支参数
    /// - `method`: SIP 方法名
    /// - `call_id`: Call-ID
    ///
    /// # 返回
    /// 事务键（branch）
    pub fn create_transaction(&self, branch: String, method: String, call_id: String) -> String {
        let tx = Transaction {
            branch: branch.clone(),
            method,
            call_id,
            created_at: Instant::now(),
            state: TransactionState::Proceeding,
        };
        let mut map = self.transactions.write().unwrap();
        map.insert(branch.clone(), tx);
        tracing::debug!("创建事务: {}", branch);
        branch
    }

    /// 查找事务
    pub fn find_transaction(&self, branch: &str) -> Option<Transaction> {
        let map = self.transactions.read().unwrap();
        map.get(branch).cloned()
    }

    /// 更新事务状态
    pub fn update_state(&self, branch: &str, new_state: TransactionState) {
        let mut map = self.transactions.write().unwrap();
        if let Some(tx) = map.get_mut(branch) {
            tracing::debug!(
                "事务 {} 状态更新: {:?} -> {:?}",
                branch,
                tx.state,
                new_state
            );
            tx.state = new_state;
        }
    }

    /// 移除事务
    pub fn remove_transaction(&self, branch: &str) {
        let mut map = self.transactions.write().unwrap();
        if map.remove(branch).is_some() {
            tracing::debug!("移除事务: {}", branch);
        }
    }

    /// 清理过期事务（超过 32 秒，Timer B）
    pub fn cleanup_expired(&self) {
        let mut map = self.transactions.write().unwrap();
        let before = map.len();
        map.retain(|branch, tx| {
            let elapsed = tx.created_at.elapsed().as_secs();
            if elapsed > 32 {
                tracing::debug!("事务 {} 已超时（{}秒），自动清理", branch, elapsed);
                false
            } else {
                true
            }
        });
        let removed = before - map.len();
        if removed > 0 {
            tracing::debug!("清理了 {} 个过期事务", removed);
        }
    }

    /// 启动后台清理任务
    pub fn start_cleanup_task(self: &std::sync::Arc<Self>) {
        let mgr = std::sync::Arc::clone(self);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(30)).await;
                mgr.cleanup_expired();
            }
        });
    }
}
