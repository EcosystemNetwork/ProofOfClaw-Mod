//! IronClaw adapter — wires Proof of Claw into ironclaw's lifecycle hook system.
//!
//! Registers hooks at the following points:
//! - `BeforeInbound` — prompt injection detection (FailClosed)
//! - `BeforeToolCall` — policy engine checks + session state recording (FailClosed)
//! - `TransformResponse` — capture 0G inference attestations (FailOpen)
//! - `OnSessionEnd` — drain session state, request 0G attestation, store trace + ZK proof

#![cfg(feature = "ironclaw")]

use crate::{
    config::AgentConfig,
    injection_detector::InjectionDetector,
    policy_engine::PolicyEngine,
    proof_generator::ProofGenerator,
    types::{
        AgentMessage, ExecutionTrace, InferenceRequest, PolicyResult, PolicySeverity,
        ToolInvocation,
    },
    zero_g::{ZeroGCompute, ZeroGStorage},
};
use anyhow::Result;
use async_trait::async_trait;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Per-session accumulated state — tool calls, policy results, and inference attestation.
///
/// Keyed by `user_id` during tool calls (ironclaw's `ToolCall` event doesn't
/// carry a session ID), then drained at `SessionEnd` which does carry one.
/// A mapping from `user_id → session_id` is maintained so we can relocate
/// state when the session ends.
#[derive(Debug, Default)]
pub struct SessionState {
    pub tool_calls: Vec<(String, serde_json::Value, serde_json::Value, bool)>,
    pub policy_results: Vec<PolicyResult>,
    pub inference_attestation: Option<String>,
}

/// Full adapter — holds all POC components needed by the hooks.
pub struct IronClawAdapter {
    pub config: AgentConfig,
    pub proof_generator: ProofGenerator,
    pub zero_g_compute: ZeroGCompute,
    pub zero_g_storage: ZeroGStorage,
    pub injection_detector: InjectionDetector,
    pub policy_engine: PolicyEngine,
    /// Per-session state accumulator, keyed by user_id (since ToolCall events
    /// don't carry session_id). Drained at SessionEnd using the session_id.
    pub sessions: RwLock<HashMap<String, SessionState>>,
    /// Maps user_id → session_id so we can relocate state at session end.
    pub user_sessions: RwLock<HashMap<String, String>>,
}

impl IronClawAdapter {
    pub async fn new(config: AgentConfig) -> Result<Self> {
        let zero_g_compute = ZeroGCompute::new(&config).await?;
        let zero_g_storage = ZeroGStorage::new(&config).await?;

        // Use from_config to pick up Boundless API URL + key from env
        let use_boundless = config.boundless_api_key.is_some();
        let proof_generator = ProofGenerator::from_config(&config, use_boundless)?;

        Ok(Self {
            config: config.clone(),
            proof_generator,
            zero_g_compute,
            zero_g_storage,
            injection_detector: InjectionDetector::new(),
            policy_engine: PolicyEngine::new(config.policy.clone()),
            sessions: RwLock::new(HashMap::new()),
            user_sessions: RwLock::new(HashMap::new()),
        })
    }

    /// Record a tool call and its policy result into the session state.
    /// Keyed by `user_id` since ironclaw's `ToolCall` event doesn't carry session_id.
    pub async fn record_tool_call(
        &self,
        user_id: &str,
        tool_name: String,
        input: serde_json::Value,
        output: serde_json::Value,
        allowed: bool,
        policy_result: PolicyResult,
    ) {
        let mut sessions = self.sessions.write().await;
        let state = sessions.entry(user_id.to_string()).or_default();
        state.tool_calls.push((tool_name, input, output, allowed));
        state.policy_results.push(policy_result);
    }

    /// Record an inference attestation, keyed by `user_id`.
    pub async fn record_attestation(&self, user_id: &str, attestation: String) {
        let mut sessions = self.sessions.write().await;
        let state = sessions.entry(user_id.to_string()).or_default();
        state.inference_attestation = Some(attestation);
    }

    /// Bind a user_id to a session_id (called on SessionStart/SessionEnd).
    pub async fn bind_session(&self, user_id: &str, session_id: &str) {
        let mut map = self.user_sessions.write().await;
        map.insert(user_id.to_string(), session_id.to_string());
    }

    /// Drain and return the accumulated session state.
    /// Looks up by session_id first, then falls back to user_id.
    pub async fn take_session_state(
        &self,
        user_id: &str,
        session_id: &str,
    ) -> SessionState {
        let mut sessions = self.sessions.write().await;
        // Try session_id first, then user_id (tool calls are keyed by user_id)
        sessions
            .remove(session_id)
            .or_else(|| sessions.remove(user_id))
            .unwrap_or_default()
    }

    /// Convert an ironclaw tool call + policy results into a POC ExecutionTrace.
    pub fn build_trace(
        &self,
        session_id: &str,
        tool_calls: Vec<(String, serde_json::Value, serde_json::Value, bool)>,
        policy_results: Vec<PolicyResult>,
        inference_attestation: Option<String>,
    ) -> ExecutionTrace {
        let timestamp = chrono::Utc::now().timestamp();

        let tool_invocations: Vec<ToolInvocation> = tool_calls
            .into_iter()
            .map(|(name, input, output, allowed)| {
                let input_hash = sha256_json(&input);
                let output_hash = sha256_json(&output);
                ToolInvocation {
                    tool_name: name,
                    input_hash,
                    output_hash,
                    capability_hash: String::new(),
                    timestamp,
                    within_policy: allowed,
                }
            })
            .collect();

        let output_commitment = {
            let mut h = Sha256::new();
            // Simplified — in production serialize the full trace
            h.update(format!("{}:{}", session_id, timestamp).as_bytes());
            format!("0x{}", hex::encode(h.finalize()))
        };

        ExecutionTrace {
            agent_id: self.config.agent_id.clone(),
            session_id: session_id.to_string(),
            timestamp,
            inference_commitment: inference_attestation.unwrap_or_default(),
            tool_invocations,
            policy_check_results: policy_results,
            output_commitment,
        }
    }

    /// Store trace on 0G Storage and generate ZK proof.
    pub async fn process_trace(&self, trace: &ExecutionTrace) -> Result<String> {
        let trace_hash = self.zero_g_storage.store_trace(trace).await?;
        tracing::info!("Trace stored on 0G Storage: {trace_hash}");

        let receipt = self.proof_generator.generate_proof(trace).await?;
        tracing::info!(
            "ZK proof generated (boundless={}): image_id={}, journal_len={}, seal_len={}",
            self.config.boundless_api_key.is_some(),
            receipt.image_id,
            receipt.journal.len(),
            receipt.seal.len()
        );

        Ok(trace_hash)
    }

    /// Request an inference attestation from 0G Compute for a session.
    ///
    /// Sends a lightweight attestation-verification prompt to 0G Compute and
    /// returns the TEE attestation signature from the response.
    pub async fn request_attestation(&self, session_id: &str) -> Result<String> {
        let request = InferenceRequest {
            system_prompt: "You are a session attestation oracle. Confirm session integrity."
                .to_string(),
            user_prompt: format!(
                "Attest execution integrity for session {session_id} on agent {}",
                self.config.agent_id
            ),
            model: Some("meta-llama/Llama-3.1-8B-Instruct".to_string()),
        };

        let response = self.zero_g_compute.inference(&request).await?;
        tracing::info!(
            "0G Compute attestation for session {session_id}: provider={}, sig_len={}",
            response.provider,
            response.attestation_signature.len()
        );

        Ok(response.attestation_signature)
    }
}

// ── SHA-256 helpers ──────────────────────────────────────────────────────────

fn sha256_json(value: &serde_json::Value) -> String {
    let s = serde_json::to_string(value).unwrap_or_default();
    let mut h = Sha256::new();
    h.update(s.as_bytes());
    format!("0x{}", hex::encode(h.finalize()))
}

// ── Ironclaw hook implementations ────────────────────────────────────────────
//
// These implement ironclaw's `Hook` trait and delegate to the adapter.

use ironclaw::hooks::{
    Hook, HookContext, HookError, HookEvent, HookFailureMode, HookOutcome, HookPoint,
};

/// Hook at `BeforeInbound` — rejects prompt injection attempts.
pub struct InjectionDetectionHook {
    detector: InjectionDetector,
}

impl InjectionDetectionHook {
    pub fn new(detector: InjectionDetector) -> Self {
        Self { detector }
    }
}

#[async_trait]
impl Hook for InjectionDetectionHook {
    fn name(&self) -> &str {
        "proof_of_claw::injection_detection"
    }

    fn hook_points(&self) -> &[HookPoint] {
        &[HookPoint::BeforeInbound]
    }

    fn failure_mode(&self) -> HookFailureMode {
        HookFailureMode::FailClosed
    }

    async fn execute(
        &self,
        event: &HookEvent,
        _ctx: &HookContext,
    ) -> Result<HookOutcome, HookError> {
        let content = match event {
            HookEvent::Inbound { content, .. } => content,
            _ => return Ok(HookOutcome::ok()),
        };

        if self.detector.detect(content) {
            tracing::warn!(
                "proof_of_claw: rejected injection attempt: {}",
                &content[..content.len().min(100)]
            );
            return Ok(HookOutcome::reject(
                "Prompt injection detected by Proof of Claw safety layer",
            ));
        }

        Ok(HookOutcome::ok())
    }
}

/// Hook at `BeforeToolCall` — checks tool against policy, records results into session state.
pub struct PolicyEnforcementHook {
    engine: PolicyEngine,
    adapter: Arc<IronClawAdapter>,
}

impl PolicyEnforcementHook {
    pub fn new(engine: PolicyEngine, adapter: Arc<IronClawAdapter>) -> Self {
        Self { engine, adapter }
    }
}

#[async_trait]
impl Hook for PolicyEnforcementHook {
    fn name(&self) -> &str {
        "proof_of_claw::policy_enforcement"
    }

    fn hook_points(&self) -> &[HookPoint] {
        &[HookPoint::BeforeToolCall]
    }

    fn failure_mode(&self) -> HookFailureMode {
        HookFailureMode::FailClosed
    }

    async fn execute(
        &self,
        event: &HookEvent,
        _ctx: &HookContext,
    ) -> Result<HookOutcome, HookError> {
        let (tool_name, parameters, user_id) = match event {
            HookEvent::ToolCall {
                tool_name,
                parameters,
                user_id,
                ..
            } => (tool_name, parameters, user_id),
            _ => return Ok(HookOutcome::ok()),
        };

        // Convert serde_json::Value to HashMap for MessagePayload
        let params: std::collections::HashMap<String, serde_json::Value> = parameters
            .as_object()
            .map(|m| m.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
            .unwrap_or_default();

        let message = AgentMessage {
            message_type: crate::types::MessageType::Execute,
            payload: crate::types::MessagePayload {
                action: tool_name.clone(),
                params,
                trace_root_hash: None,
                proof_receipt: None,
                required_approval: None,
            },
            nonce: 0,
            timestamp: chrono::Utc::now().timestamp(),
        };
        let dummy_inference = crate::types::InferenceResponse {
            content: String::new(),
            attestation_signature: String::new(),
            provider: "0g-compute".to_string(),
        };

        let result = self.engine.check(&message, &dummy_inference);

        // Record tool call + policy result into session state (keyed by user_id)
        let allowed = !matches!(result.severity, PolicySeverity::Block);
        self.adapter
            .record_tool_call(
                user_id,
                tool_name.clone(),
                parameters.clone(),
                serde_json::Value::Null, // output captured after execution
                allowed,
                result.clone(),
            )
            .await;

        match result.severity {
            PolicySeverity::Block => {
                tracing::warn!(
                    "proof_of_claw: blocked tool '{tool_name}': {}",
                    result.details
                );
                Ok(HookOutcome::reject(format!(
                    "Policy violation: {}. Tool '{}' is not permitted.",
                    result.details, tool_name
                )))
            }
            PolicySeverity::Warn => {
                tracing::warn!(
                    "proof_of_claw: warning for tool '{tool_name}': {}",
                    result.details
                );
                Ok(HookOutcome::ok()) // Warn but don't block
            }
            PolicySeverity::Sanitize | PolicySeverity::Pass => Ok(HookOutcome::ok()),
        }
    }
}

/// Hook at `OnSessionEnd` — stores execution trace and generates ZK proof.
pub struct ProofGenerationHook {
    adapter: Arc<IronClawAdapter>,
}

impl ProofGenerationHook {
    pub fn new(adapter: Arc<IronClawAdapter>) -> Self {
        Self { adapter }
    }
}

#[async_trait]
impl Hook for ProofGenerationHook {
    fn name(&self) -> &str {
        "proof_of_claw::proof_generation"
    }

    fn hook_points(&self) -> &[HookPoint] {
        &[HookPoint::OnSessionEnd]
    }

    fn timeout(&self) -> std::time::Duration {
        std::time::Duration::from_secs(30)
    }

    async fn execute(
        &self,
        event: &HookEvent,
        _ctx: &HookContext,
    ) -> Result<HookOutcome, HookError> {
        let (user_id, session_id) = match event {
            HookEvent::SessionEnd {
                user_id,
                session_id,
            } => (user_id, session_id),
            _ => return Ok(HookOutcome::ok()),
        };

        // Drain accumulated session state — tries session_id key first,
        // falls back to user_id (tool calls are keyed by user_id).
        let state = self
            .adapter
            .take_session_state(user_id, session_id)
            .await;

        // If no attestation was captured during the session, request one from
        // 0G Compute now — this verifies the inference pipeline end-to-end.
        let attestation = match state.inference_attestation {
            Some(att) => Some(att),
            None if !state.tool_calls.is_empty() => {
                match self.adapter.request_attestation(session_id).await {
                    Ok(att) => Some(att),
                    Err(e) => {
                        tracing::warn!(
                            "proof_of_claw: failed to get 0G attestation for {session_id}: {e}"
                        );
                        None
                    }
                }
            }
            None => None,
        };

        let trace = self.adapter.build_trace(
            session_id,
            state.tool_calls,
            state.policy_results,
            attestation,
        );

        match self.adapter.process_trace(&trace).await {
            Ok(trace_hash) => {
                tracing::info!(
                    "proof_of_claw: session {session_id} trace committed: {trace_hash}"
                );
                Ok(HookOutcome::ok())
            }
            Err(e) => {
                tracing::error!("proof_of_claw: failed to process trace: {e}");
                // Fail open — don't block session end for proof failures
                Ok(HookOutcome::ok())
            }
        }
    }
}

/// Hook at `TransformResponse` — captures inference attestations from outbound
/// responses before they're sent. Parses TEE attestation fields from the
/// response content and records them into session state for the final trace.
pub struct InferenceAttestationHook {
    adapter: Arc<IronClawAdapter>,
}

impl InferenceAttestationHook {
    pub fn new(adapter: Arc<IronClawAdapter>) -> Self {
        Self { adapter }
    }
}

#[async_trait]
impl Hook for InferenceAttestationHook {
    fn name(&self) -> &str {
        "proof_of_claw::inference_attestation"
    }

    fn hook_points(&self) -> &[HookPoint] {
        &[HookPoint::TransformResponse]
    }

    fn failure_mode(&self) -> HookFailureMode {
        // Attestation capture is best-effort — don't block responses on failure
        HookFailureMode::FailOpen
    }

    async fn execute(
        &self,
        event: &HookEvent,
        _ctx: &HookContext,
    ) -> Result<HookOutcome, HookError> {
        let (user_id, response) = match event {
            HookEvent::ResponseTransform {
                user_id, response, ..
            } => (user_id, response),
            _ => return Ok(HookOutcome::ok()),
        };

        // Try to extract a TEE attestation from the response content.
        // If the response came from 0G Compute, it may contain attestation fields.
        let attestation =
            if let Some(att) = crate::zero_g::parse_attestation_from(response) {
                att
            } else {
                // Hash the response content as a local attestation fallback
                let mut h = Sha256::new();
                h.update(response.as_bytes());
                format!("0x{}", hex::encode(h.finalize()))
            };

        self.adapter
            .record_attestation(user_id, attestation)
            .await;

        Ok(HookOutcome::ok())
    }
}
