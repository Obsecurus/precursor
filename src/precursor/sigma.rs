use std::collections::{HashMap, HashSet};
use std::path::Path;
use xxhash_rust::xxh3::xxh3_64;

#[derive(Clone, Debug)]
pub struct SigmaPatternSpec {
    pub regex: String,
}

#[derive(Clone, Debug)]
pub struct SigmaRulePlan {
    pub rule_name: String,
    pub rule_slug: String,
    pub condition: SigmaConditionExpr,
    pub selector_capture_names: HashMap<String, Vec<String>>,
    pub pattern_specs: Vec<SigmaPatternSpec>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SigmaConditionExpr {
    Selector(String),
    CountOf {
        quantifier: SigmaCountQuantifier,
        target: String,
    },
    Not(Box<SigmaConditionExpr>),
    And(Box<SigmaConditionExpr>, Box<SigmaConditionExpr>),
    Or(Box<SigmaConditionExpr>, Box<SigmaConditionExpr>),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SigmaCountQuantifier {
    All,
    AtLeast(usize),
}

impl SigmaConditionExpr {
    pub fn evaluate(&self, selector_hits: &HashMap<String, bool>) -> bool {
        match self {
            SigmaConditionExpr::Selector(selector) => {
                selector_hits.get(selector).copied().unwrap_or(false)
            }
            SigmaConditionExpr::CountOf { quantifier, target } => {
                let matched_selectors = matching_selectors(selector_hits, target);
                if matched_selectors.is_empty() {
                    return false;
                }
                let hit_count = matched_selectors
                    .iter()
                    .filter(|selector| selector_hits.get::<str>(selector).copied().unwrap_or(false))
                    .count();
                match quantifier {
                    SigmaCountQuantifier::All => hit_count == matched_selectors.len(),
                    SigmaCountQuantifier::AtLeast(minimum) => hit_count >= *minimum,
                }
            }
            SigmaConditionExpr::Not(inner) => !inner.evaluate(selector_hits),
            SigmaConditionExpr::And(left, right) => {
                left.evaluate(selector_hits) && right.evaluate(selector_hits)
            }
            SigmaConditionExpr::Or(left, right) => {
                left.evaluate(selector_hits) || right.evaluate(selector_hits)
            }
        }
    }
}

pub fn load_sigma_rule_plan(rule_path: &Path) -> Result<SigmaRulePlan, String> {
    let yaml_raw = std::fs::read_to_string(rule_path).map_err(|err| {
        format!(
            "unable to read Sigma rule file {}: {}",
            rule_path.display(),
            err
        )
    })?;

    let mut rule_name = rule_path
        .file_stem()
        .map(|value| value.to_string_lossy().to_string())
        .unwrap_or_else(|| "sigma_rule".to_string());
    let mut rule_id = rule_name.to_string();

    let mut in_detection = false;
    let mut detection_indent = 0usize;
    let mut current_selector: Option<String> = None;
    let mut current_field: Option<String> = None;
    let mut condition_raw = "1 of them".to_string();

    let mut capture_index: HashMap<String, usize> = HashMap::new();
    let mut selector_capture_names: HashMap<String, Vec<String>> = HashMap::new();
    let mut pattern_specs = Vec::new();

    for raw_line in yaml_raw.lines() {
        let line = raw_line.trim_end();
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let indent = yaml_leading_space_count(line);

        if !in_detection {
            if indent == 0 {
                if let Some(rest) = parse_mapping_line(trimmed, "title") {
                    rule_name = strip_yaml_quotes(rest).to_string();
                } else if let Some(rest) = parse_mapping_line(trimmed, "id") {
                    rule_id = strip_yaml_quotes(rest).to_string();
                } else if trimmed == "detection:" {
                    in_detection = true;
                    detection_indent = indent;
                }
            }
            continue;
        }

        if indent <= detection_indent {
            break;
        }

        if let Some(rest) = parse_mapping_line(trimmed, "condition") {
            condition_raw = strip_yaml_quotes(rest).to_string();
            current_selector = None;
            current_field = None;
            continue;
        }

        if indent == detection_indent + 2 && !trimmed.starts_with('-') {
            if trimmed.ends_with(':') {
                current_selector = Some(trimmed.trim_end_matches(':').trim().to_string());
                current_field = None;
                continue;
            }
            if let Some((selector, inline_value)) = split_yaml_key_value(trimmed) {
                current_selector = Some(selector.to_string());
                current_field = None;
                if !inline_value.is_empty() {
                    let Some(selector_name) = current_selector.as_deref() else {
                        continue;
                    };
                    add_sigma_patterns(
                        selector_name,
                        None,
                        &[],
                        vec![strip_yaml_quotes(inline_value).to_string()],
                        &mut capture_index,
                        &mut selector_capture_names,
                        &mut pattern_specs,
                        rule_id.as_str(),
                    );
                }
                continue;
            }
        }

        if !trimmed.starts_with('-') {
            if trimmed.ends_with(':') {
                current_field = Some(trimmed.trim_end_matches(':').trim().to_string());
                continue;
            }
            if let Some((field, inline_value)) = split_yaml_key_value(trimmed) {
                current_field = Some(field.to_string());
                if !inline_value.is_empty() {
                    let Some(selector_name) = current_selector.as_deref() else {
                        continue;
                    };
                    let field_name = current_field.as_deref();
                    let (field_base, modifiers) = parse_field_modifiers(field_name);
                    add_sigma_patterns(
                        selector_name,
                        field_base,
                        modifiers.as_slice(),
                        vec![strip_yaml_quotes(inline_value).to_string()],
                        &mut capture_index,
                        &mut selector_capture_names,
                        &mut pattern_specs,
                        rule_id.as_str(),
                    );
                }
                continue;
            }
            continue;
        }

        let value_text = strip_yaml_quotes(trimmed.trim_start_matches('-').trim()).to_string();
        if value_text.is_empty() {
            continue;
        }
        let Some(selector_name) = current_selector.as_deref() else {
            continue;
        };
        let field_name = current_field.as_deref();
        let (field_base, modifiers) = parse_field_modifiers(field_name);
        add_sigma_patterns(
            selector_name,
            field_base,
            modifiers.as_slice(),
            vec![value_text],
            &mut capture_index,
            &mut selector_capture_names,
            &mut pattern_specs,
            rule_id.as_str(),
        );
    }

    if !in_detection {
        return Err(format!(
            "Sigma rule {} is missing a detection block",
            rule_path.display()
        ));
    }
    if pattern_specs.is_empty() {
        return Err(format!(
            "Sigma rule {} did not yield any keyword patterns",
            rule_path.display()
        ));
    }

    let condition = parse_sigma_condition(condition_raw.as_str()).map_err(|err| {
        format!(
            "unable to parse condition in Sigma rule {}: {}",
            rule_path.display(),
            err
        )
    })?;

    Ok(SigmaRulePlan {
        rule_name,
        rule_slug: sanitize_capture_name(rule_id.as_str()),
        condition,
        selector_capture_names,
        pattern_specs,
    })
}

pub fn matching_sigma_rules<'a>(
    rule_plans: &'a [SigmaRulePlan],
    matched_tags: &[String],
) -> Vec<&'a SigmaRulePlan> {
    if rule_plans.is_empty() || matched_tags.is_empty() {
        return Vec::new();
    }
    let matched_set: HashSet<&str> = matched_tags.iter().map(String::as_str).collect();
    let mut hits = Vec::new();
    for rule in rule_plans {
        let selector_hits = selector_hits_for_rule(rule, &matched_set);
        if rule.condition.evaluate(&selector_hits) {
            hits.push(rule);
        }
    }
    hits
}

fn selector_hits_for_rule(
    rule: &SigmaRulePlan,
    matched_tags: &HashSet<&str>,
) -> HashMap<String, bool> {
    let mut selector_hits = HashMap::new();
    for (selector_name, capture_names) in &rule.selector_capture_names {
        let hit = capture_names
            .iter()
            .any(|capture_name| matched_tags.contains(capture_name.as_str()));
        selector_hits.insert(selector_name.to_string(), hit);
    }
    selector_hits
}

fn parse_mapping_line<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    let prefix = format!("{}:", key);
    if line.starts_with(prefix.as_str()) {
        Some(line[prefix.len()..].trim())
    } else {
        None
    }
}

fn split_yaml_key_value(line: &str) -> Option<(&str, &str)> {
    let (left, right) = line.split_once(':')?;
    Some((left.trim(), right.trim()))
}

fn parse_field_modifiers(field_name: Option<&str>) -> (Option<&str>, Vec<&str>) {
    let Some(field_name) = field_name else {
        return (None, Vec::new());
    };
    let mut parts = field_name.split('|');
    let field_base = parts.next();
    let modifiers = parts.collect::<Vec<&str>>();
    (field_base, modifiers)
}

#[allow(clippy::too_many_arguments)]
fn add_sigma_patterns(
    selector_name: &str,
    field_name: Option<&str>,
    modifiers: &[&str],
    values: Vec<String>,
    capture_index: &mut HashMap<String, usize>,
    selector_capture_names: &mut HashMap<String, Vec<String>>,
    pattern_specs: &mut Vec<SigmaPatternSpec>,
    rule_id: &str,
) {
    let rule_slug = sanitize_capture_name(rule_id);
    for value in values {
        let stem = if let Some(field) = field_name {
            format!(
                "{}_{}",
                sanitize_capture_name(selector_name),
                sanitize_capture_name(field)
            )
        } else {
            sanitize_capture_name(selector_name)
        };
        let entry = capture_index.entry(stem.clone()).or_insert(0);
        let capture_name = sigma_capture_name(rule_slug.as_str(), stem.as_str(), *entry);
        *entry += 1;
        let rendered = sigma_value_to_pcre(value.as_str(), modifiers);
        let regex = format!("(?<{}>{})", capture_name, rendered);
        selector_capture_names
            .entry(selector_name.to_string())
            .or_default()
            .push(capture_name.clone());
        pattern_specs.push(SigmaPatternSpec { regex });
    }
}

fn yaml_leading_space_count(line: &str) -> usize {
    line.chars().take_while(|ch| *ch == ' ').count()
}

fn strip_yaml_quotes(value: &str) -> &str {
    let trimmed = value.trim();
    if trimmed.len() < 2 {
        return trimmed;
    }
    let first = trimmed.chars().next().unwrap_or_default();
    let last = trimmed.chars().last().unwrap_or_default();
    if (first == '\'' && last == '\'') || (first == '"' && last == '"') {
        &trimmed[1..trimmed.len() - 1]
    } else {
        trimmed
    }
}

fn sanitize_capture_name(input: &str) -> String {
    let mut out = String::new();
    for ch in input.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
        } else {
            out.push('_');
        }
    }
    let out = out.trim_matches('_').to_string();
    if out.is_empty() {
        "sigma_match".to_string()
    } else if out
        .chars()
        .next()
        .map(|ch| ch.is_ascii_digit())
        .unwrap_or(false)
    {
        format!("sigma_{}", out)
    } else {
        out
    }
}

fn sigma_capture_name(rule_slug: &str, stem: &str, ordinal: usize) -> String {
    // Some PCRE2 builds enforce 32 code units for named captures (notably on Windows).
    // Use a deterministic compact name so Sigma-generated patterns are portable.
    const PCRE2_CAPTURE_NAME_MAX: usize = 32;
    let digest = xxh3_64(format!("{}:{}:{}", rule_slug, stem, ordinal).as_bytes());
    let mut name = format!("sigma_{:016x}_{}", digest, ordinal);
    if name.len() > PCRE2_CAPTURE_NAME_MAX {
        name = format!("sigma_{:016x}", digest);
    }
    name
}

fn sigma_escape_literal(input: &str) -> String {
    let mut escaped = String::new();
    for ch in input.chars() {
        match ch {
            '\\' | '.' | '+' | '^' | '$' | '{' | '}' | '(' | ')' | '[' | ']' | '|' => {
                escaped.push('\\');
                escaped.push(ch);
            }
            '*' => escaped.push_str(".*"),
            '?' => escaped.push('.'),
            _ => escaped.push(ch),
        }
    }
    escaped
}

fn sigma_value_to_pcre(value: &str, modifiers: &[&str]) -> String {
    if modifiers.iter().any(|modifier| *modifier == "re") {
        return value.to_string();
    }
    let wildcard_present = value.contains('*') || value.contains('?');
    let escaped = sigma_escape_literal(value);

    if modifiers.iter().any(|modifier| *modifier == "contains") && !wildcard_present {
        format!(".*{}.*", escaped)
    } else if modifiers.iter().any(|modifier| *modifier == "startswith") && !wildcard_present {
        format!("{}.*", escaped)
    } else if modifiers.iter().any(|modifier| *modifier == "endswith") && !wildcard_present {
        format!(".*{}", escaped)
    } else {
        escaped
    }
}

fn matching_selectors<'a>(selector_hits: &'a HashMap<String, bool>, target: &str) -> Vec<&'a str> {
    if target.eq_ignore_ascii_case("them") {
        return selector_hits.keys().map(|key| key.as_str()).collect();
    }
    selector_hits
        .keys()
        .filter_map(|selector| {
            if wildcard_match(target, selector.as_str()) {
                Some(selector.as_str())
            } else {
                None
            }
        })
        .collect()
}

fn wildcard_match(pattern: &str, candidate: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if !pattern.contains('*') {
        return pattern == candidate;
    }
    let parts: Vec<&str> = pattern.split('*').collect();
    let mut cursor = 0usize;
    for (idx, part) in parts.iter().enumerate() {
        if part.is_empty() {
            continue;
        }
        if idx == 0 && !pattern.starts_with('*') {
            if !candidate[cursor..].starts_with(part) {
                return false;
            }
            cursor += part.len();
            continue;
        }
        if idx == parts.len() - 1 && !pattern.ends_with('*') {
            return candidate[cursor..].ends_with(part);
        }
        if let Some(found) = candidate[cursor..].find(part) {
            cursor += found + part.len();
        } else {
            return false;
        }
    }
    true
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum ConditionToken {
    LParen,
    RParen,
    And,
    Or,
    Not,
    All,
    Of,
    Them,
    Number(usize),
    Ident(String),
}

fn tokenize_condition(expression: &str) -> Result<Vec<ConditionToken>, String> {
    let mut out = Vec::new();
    let chars: Vec<char> = expression.chars().collect();
    let mut idx = 0usize;
    while idx < chars.len() {
        let ch = chars[idx];
        if ch.is_whitespace() {
            idx += 1;
            continue;
        }
        if ch == '(' {
            out.push(ConditionToken::LParen);
            idx += 1;
            continue;
        }
        if ch == ')' {
            out.push(ConditionToken::RParen);
            idx += 1;
            continue;
        }
        if ch.is_ascii_digit() {
            let start = idx;
            idx += 1;
            while idx < chars.len() && chars[idx].is_ascii_digit() {
                idx += 1;
            }
            let parsed: String = chars[start..idx].iter().collect();
            let parsed = parsed
                .parse::<usize>()
                .map_err(|err| format!("invalid numeric token '{}': {}", parsed, err))?;
            out.push(ConditionToken::Number(parsed));
            continue;
        }
        if ch.is_ascii_alphanumeric() || ch == '_' || ch == '*' || ch == '-' || ch == '.' {
            let start = idx;
            idx += 1;
            while idx < chars.len()
                && (chars[idx].is_ascii_alphanumeric()
                    || chars[idx] == '_'
                    || chars[idx] == '*'
                    || chars[idx] == '-'
                    || chars[idx] == '.')
            {
                idx += 1;
            }
            let token: String = chars[start..idx].iter().collect();
            let lowered = token.to_ascii_lowercase();
            let keyword = match lowered.as_str() {
                "and" => Some(ConditionToken::And),
                "or" => Some(ConditionToken::Or),
                "not" => Some(ConditionToken::Not),
                "all" => Some(ConditionToken::All),
                "of" => Some(ConditionToken::Of),
                "them" => Some(ConditionToken::Them),
                _ => None,
            };
            out.push(keyword.unwrap_or(ConditionToken::Ident(token)));
            continue;
        }
        return Err(format!("unsupported token '{}' in condition", ch));
    }
    Ok(out)
}

pub fn parse_sigma_condition(expression: &str) -> Result<SigmaConditionExpr, String> {
    let tokens = tokenize_condition(expression)?;
    let mut parser = ConditionParser { tokens, index: 0 };
    let expr = parser.parse_or()?;
    if parser.index < parser.tokens.len() {
        return Err("unexpected trailing tokens".to_string());
    }
    Ok(expr)
}

struct ConditionParser {
    tokens: Vec<ConditionToken>,
    index: usize,
}

impl ConditionParser {
    fn current(&self) -> Option<&ConditionToken> {
        self.tokens.get(self.index)
    }

    fn advance(&mut self) {
        self.index += 1;
    }

    fn parse_or(&mut self) -> Result<SigmaConditionExpr, String> {
        let mut node = self.parse_and()?;
        while matches!(self.current(), Some(ConditionToken::Or)) {
            self.advance();
            let right = self.parse_and()?;
            node = SigmaConditionExpr::Or(Box::new(node), Box::new(right));
        }
        Ok(node)
    }

    fn parse_and(&mut self) -> Result<SigmaConditionExpr, String> {
        let mut node = self.parse_unary()?;
        while matches!(self.current(), Some(ConditionToken::And)) {
            self.advance();
            let right = self.parse_unary()?;
            node = SigmaConditionExpr::And(Box::new(node), Box::new(right));
        }
        Ok(node)
    }

    fn parse_unary(&mut self) -> Result<SigmaConditionExpr, String> {
        if matches!(self.current(), Some(ConditionToken::Not)) {
            self.advance();
            let inner = self.parse_unary()?;
            return Ok(SigmaConditionExpr::Not(Box::new(inner)));
        }
        self.parse_primary()
    }

    fn parse_primary(&mut self) -> Result<SigmaConditionExpr, String> {
        match self.current() {
            Some(ConditionToken::LParen) => {
                self.advance();
                let expr = self.parse_or()?;
                if !matches!(self.current(), Some(ConditionToken::RParen)) {
                    return Err("expected ')'".to_string());
                }
                self.advance();
                Ok(expr)
            }
            Some(ConditionToken::All) => {
                self.advance();
                self.parse_count_of(SigmaCountQuantifier::All)
            }
            Some(ConditionToken::Number(value)) => {
                let value = *value;
                self.advance();
                self.parse_count_of(SigmaCountQuantifier::AtLeast(value))
            }
            Some(ConditionToken::Ident(selector)) => {
                let selector = selector.to_string();
                self.advance();
                Ok(SigmaConditionExpr::Selector(selector))
            }
            _ => Err("unexpected token in condition".to_string()),
        }
    }

    fn parse_count_of(
        &mut self,
        quantifier: SigmaCountQuantifier,
    ) -> Result<SigmaConditionExpr, String> {
        if !matches!(self.current(), Some(ConditionToken::Of)) {
            return Err("expected 'of'".to_string());
        }
        self.advance();
        let target = match self.current() {
            Some(ConditionToken::Them) => "them".to_string(),
            Some(ConditionToken::Ident(value)) => value.to_string(),
            _ => return Err("expected selector name or 'them' after 'of'".to_string()),
        };
        self.advance();
        Ok(SigmaConditionExpr::CountOf { quantifier, target })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::Write;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    struct TempFileGuard {
        path: PathBuf,
    }

    impl Drop for TempFileGuard {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.path);
        }
    }

    fn temp_rule_path(stem: &str) -> (PathBuf, TempFileGuard) {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let path =
            std::env::temp_dir().join(format!("{}-{}-{}.yml", stem, std::process::id(), nanos));
        let guard = TempFileGuard {
            path: path.to_path_buf(),
        };
        (path, guard)
    }

    #[test]
    fn parse_and_evaluate_basic_condition() {
        let expr = parse_sigma_condition("keywords and not filter").expect("parse condition");
        let mut selector_hits = HashMap::new();
        selector_hits.insert("keywords".to_string(), true);
        selector_hits.insert("filter".to_string(), false);
        assert!(expr.evaluate(&selector_hits));
    }

    #[test]
    fn parse_count_of_selector_glob() {
        let expr = parse_sigma_condition("1 of selection*").expect("parse condition");
        let mut selector_hits = HashMap::new();
        selector_hits.insert("selection_a".to_string(), false);
        selector_hits.insert("selection_b".to_string(), true);
        assert!(expr.evaluate(&selector_hits));
    }

    #[test]
    fn load_rule_plan_and_condition_match() {
        let (path, _guard) = temp_rule_path("precursor-sigma-condition");
        let mut file = File::create(&path).expect("create temp sigma file");
        let yaml = r#"title: Sigma Condition Test
id: sigma-condition-test
detection:
  selection_cmd:
    CommandLine|contains:
      - '/bin/sh'
  selection_fetch:
    CommandLine|contains:
      - 'curl '
  condition: selection_cmd and selection_fetch
"#;
        file.write_all(yaml.as_bytes()).expect("write sigma rule");
        let plan = load_sigma_rule_plan(path.as_path()).expect("load rule plan");
        assert_eq!(plan.rule_slug, "sigma_condition_test");
        assert_eq!(plan.pattern_specs.len(), 2);
        let matched = plan
            .selector_capture_names
            .values()
            .flat_map(|captures| captures.iter().cloned())
            .collect::<Vec<String>>();
        assert!(matched.iter().all(|capture_name| capture_name.len() <= 32));
        let plans = [plan];
        let hits = matching_sigma_rules(&plans, &matched);
        assert_eq!(hits.len(), 1);
    }

    #[test]
    fn sigma_capture_name_respects_portable_pcre2_limit() {
        let capture_name = sigma_capture_name(
            "sigma_condition_filter_test",
            "selection_fetch_commandline",
            123_456_789,
        );
        assert!(capture_name.starts_with("sigma_"));
        assert!(capture_name.len() <= 32);
    }
}
