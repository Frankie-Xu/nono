//! The `decision` vocabulary the tool sandbox writes into command policy audit
//! events.
//!
//! Emitters name a variant rather than a string literal, so a new decision
//! cannot reach the audit log without declaring how it folds into a session
//! rollup.

use nono::undo::CommandPolicyOutcome;

/// Declare the vocabulary once: variant, persisted string, and the outcome the
/// decision folds into.
///
/// Single-sourcing the table is what closes the gap the vocabulary used to
/// have. The emitters, the string written to the log, and the classification
/// all come from these rows, so there is no second list to leave un-updated.
macro_rules! command_policy_decisions {
    ($($variant:ident => $persisted:literal => $outcome:ident,)+) => {
        /// A decision recorded for a mediated command.
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub(crate) enum CommandPolicyDecision {
            $($variant,)+
        }

        impl CommandPolicyDecision {
            /// The string persisted as the event's `decision` field.
            pub(crate) fn as_str(self) -> &'static str {
                match self {
                    $(Self::$variant => $persisted,)+
                }
            }

            /// How the decision folds into a session rollup.
            pub(crate) fn outcome(self) -> CommandPolicyOutcome {
                match self {
                    $(Self::$variant => CommandPolicyOutcome::$outcome,)+
                }
            }
        }
    };
}

command_policy_decisions! {
    Allowed => "allowed" => Allowed,
    ApproveDenied => "approve_denied" => Denied,
    ApproveGranted => "approve_granted" => Pending,
    Capture => "capture" => Allowed,
    CaptureCredential => "capture_credential" => Allowed,
    CaptureCredentialCached => "capture_credential_cached" => Allowed,
    Denied => "denied" => Denied,
    Exec => "exec" => Allowed,
    InvocationAllowed => "invocation_allowed" => Pending,
    InvocationApproveDenied => "invocation_approve_denied" => Denied,
    InvocationApproveGranted => "invocation_approve_granted" => Pending,
    InvocationDenied => "invocation_denied" => Denied,
    Respond => "respond" => Allowed,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A log has to re-summarize the way it summarized when it was written, so
    /// what an existing decision persists as and folds into is asserted here
    /// rather than derived from the table being checked.
    const FROZEN: [(CommandPolicyDecision, &str, CommandPolicyOutcome); 13] = [
        (
            CommandPolicyDecision::Allowed,
            "allowed",
            CommandPolicyOutcome::Allowed,
        ),
        (
            CommandPolicyDecision::Respond,
            "respond",
            CommandPolicyOutcome::Allowed,
        ),
        (
            CommandPolicyDecision::Capture,
            "capture",
            CommandPolicyOutcome::Allowed,
        ),
        (
            CommandPolicyDecision::Exec,
            "exec",
            CommandPolicyOutcome::Allowed,
        ),
        (
            CommandPolicyDecision::CaptureCredential,
            "capture_credential",
            CommandPolicyOutcome::Allowed,
        ),
        (
            CommandPolicyDecision::CaptureCredentialCached,
            "capture_credential_cached",
            CommandPolicyOutcome::Allowed,
        ),
        (
            CommandPolicyDecision::Denied,
            "denied",
            CommandPolicyOutcome::Denied,
        ),
        (
            CommandPolicyDecision::InvocationDenied,
            "invocation_denied",
            CommandPolicyOutcome::Denied,
        ),
        (
            CommandPolicyDecision::InvocationApproveDenied,
            "invocation_approve_denied",
            CommandPolicyOutcome::Denied,
        ),
        (
            CommandPolicyDecision::ApproveDenied,
            "approve_denied",
            CommandPolicyOutcome::Denied,
        ),
        (
            CommandPolicyDecision::InvocationAllowed,
            "invocation_allowed",
            CommandPolicyOutcome::Pending,
        ),
        (
            CommandPolicyDecision::InvocationApproveGranted,
            "invocation_approve_granted",
            CommandPolicyOutcome::Pending,
        ),
        (
            CommandPolicyDecision::ApproveGranted,
            "approve_granted",
            CommandPolicyOutcome::Pending,
        ),
    ];

    #[test]
    fn the_decision_to_outcome_mapping_is_frozen() {
        for (decision, persisted, outcome) in FROZEN {
            assert_eq!(
                decision.as_str(),
                persisted,
                "{decision:?} persisted unexpectedly"
            );
            assert_eq!(
                decision.outcome(),
                outcome,
                "{decision:?} classified unexpectedly"
            );
        }
    }
}
