//! Language-neutral gate evaluator. Interprets `gate/rules.json` only — no
//! hardcoded grades or actions. The same rule table is the single source that
//! the TS UI (`soksak-plugin-db-studio/src/features/db/gate/gate.ts`) consumes,
//! so both sides classify verdicts identically (plan §5, 선행정리-3). The
//! `gate/` copies are build-time syncs of the plugin's canonical files.

use serde::Deserialize;

/// The rule table, embedded at build time so classification is deterministic.
const RULES_JSON: &str = include_str!("../gate/rules.json");

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OpClass {
    Read,
    Write,
    Ddl,
    #[serde(rename = "profileMutation")]
    ProfileMutation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum GateAction {
    Allow,
    Confirm,
    Deny,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Environment {
    Dev,
    Staging,
    Prod,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GateProfile {
    #[serde(default)]
    pub environment: Option<Environment>,
    #[serde(default)]
    pub read_only: Option<bool>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GateInput {
    #[serde(default)]
    pub command_id: Option<String>,
    pub op_class: OpClass,
    #[serde(default)]
    pub profile: GateProfile,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GateVerdict {
    pub grade: u8,
    pub action: GateAction,
    pub rule: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct RuleProfileMatch {
    #[serde(default)]
    environment: Option<Environment>,
    #[serde(default, rename = "readOnly")]
    read_only: Option<bool>,
}

#[derive(Debug, Clone, Deserialize)]
struct RuleMatch {
    #[serde(default, rename = "opClass")]
    op_class: Option<OpClass>,
    #[serde(default, rename = "commandId")]
    command_id: Option<String>,
    #[serde(default)]
    profile: Option<RuleProfileMatch>,
}

#[derive(Debug, Clone, Deserialize)]
struct Rule {
    id: String,
    #[serde(default)]
    r#match: Option<RuleMatch>,
    grade: u8,
    action: GateAction,
}

#[derive(Debug, Clone, Deserialize)]
struct RulesTable {
    #[allow(dead_code)]
    version: u32,
    rules: Vec<Rule>,
}

fn table() -> &'static RulesTable {
    use std::sync::OnceLock;
    static TABLE: OnceLock<RulesTable> = OnceLock::new();
    TABLE.get_or_init(|| {
        serde_json::from_str(RULES_JSON).expect("gate/rules.json is a valid rule table")
    })
}

/// A rule matches when every field it declares under `match` equals the input;
/// `profile` sub-fields match individually. A declared-but-empty `match` (or an
/// absent one) matches anything — the catch-all.
fn matches(rule: &Rule, input: &GateInput) -> bool {
    let m = match &rule.r#match {
        Some(m) => m,
        None => return true,
    };
    if let Some(op_class) = &m.op_class {
        if *op_class != input.op_class {
            return false;
        }
    }
    if let Some(command_id) = &m.command_id {
        if Some(command_id) != input.command_id.as_ref() {
            return false;
        }
    }
    if let Some(profile) = &m.profile {
        if let Some(environment) = &profile.environment {
            if Some(*environment) != input.profile.environment {
                return false;
            }
        }
        if let Some(read_only) = profile.read_only {
            if Some(read_only) != input.profile.read_only {
                return false;
            }
        }
    }
    true
}

/// First matching rule wins. `rules.json` ends with a catch-all `default-deny`
/// so a verdict is always produced (fail-closed); the `no-match` fallback mirrors
/// the TS evaluator's final return.
pub fn classify_gate(input: &GateInput) -> GateVerdict {
    for rule in &table().rules {
        if matches(rule, input) {
            return GateVerdict {
                grade: rule.grade,
                action: rule.action,
                rule: rule.id.clone(),
            };
        }
    }
    GateVerdict {
        grade: 3,
        action: GateAction::Deny,
        rule: "no-match".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CASES_JSON: &str = include_str!("../gate/cases.json");

    #[derive(Deserialize)]
    struct ExpectVerdict {
        grade: u8,
        action: GateAction,
    }

    #[derive(Deserialize)]
    struct ConformanceCase {
        name: String,
        input: GateInput,
        expect: ExpectVerdict,
    }

    #[test]
    fn conformance_matches_ts_verdicts() {
        let cases: Vec<ConformanceCase> =
            serde_json::from_str(CASES_JSON).expect("gate/cases.json parses");
        assert!(!cases.is_empty(), "conformance suite must not be empty");
        for case in &cases {
            let verdict = classify_gate(&case.input);
            assert_eq!(
                verdict.grade, case.expect.grade,
                "grade mismatch for case: {}",
                case.name
            );
            assert_eq!(
                verdict.action, case.expect.action,
                "action mismatch for case: {}",
                case.name
            );
        }
    }
}
