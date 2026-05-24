//! Core policy model primitives for Heim.
//!
//! These types describe named JIT credential grants and the local policy
//! constraints around who may request them, which commands they may wrap, and
//! how approval is obtained.

mod approval;
mod command;
mod grant;
mod requester;

pub use approval::{
    ApprovalMode, ApprovalPolicy, ApprovalTransportName, ApprovalTransportNameError,
};
pub use command::{CommandRule, CommandRuleError};
pub use grant::{
    GrantName, GrantNameError, GrantPolicy, GrantPolicyError, ProviderName, ProviderNameError,
};
pub use requester::{BinaryName, BinaryNameError, RequesterRule};
