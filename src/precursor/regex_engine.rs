#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RegexEngine {
    Pcre2,
    Vectorscan,
}

impl RegexEngine {
    pub fn from_str(value: &str) -> Result<Self, String> {
        match value {
            "pcre2" => Ok(Self::Pcre2),
            "vectorscan" => Ok(Self::Vectorscan),
            _ => Err(format!("Unsupported regex engine '{}'", value)),
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pcre2 => "pcre2",
            Self::Vectorscan => "vectorscan",
        }
    }
}

pub fn vectorscan_compatibility_issues(pattern: &str) -> Vec<&'static str> {
    let mut issues = Vec::new();
    if pattern.contains("(?<=") || pattern.contains("(?<!") {
        issues.push("lookbehind assertions are not supported");
    }
    if pattern.contains("\\1")
        || pattern.contains("\\2")
        || pattern.contains("\\3")
        || pattern.contains("\\4")
        || pattern.contains("\\5")
        || pattern.contains("\\6")
        || pattern.contains("\\7")
        || pattern.contains("\\8")
        || pattern.contains("\\9")
    {
        issues.push("backreferences are not supported");
    }
    if pattern.contains("(?R") || pattern.contains("(?&") {
        issues.push("recursive/subroutine constructs are not supported");
    }
    if pattern.contains("(?>") {
        issues.push("atomic groups may be incompatible");
    }
    if pattern.contains("(?(") {
        issues.push("conditional expressions are not supported");
    }
    if pattern.contains("(?C") {
        issues.push("callouts are not supported");
    }
    issues
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn regex_engine_round_trip() {
        assert_eq!(
            RegexEngine::from_str("pcre2").expect("parse pcre2"),
            RegexEngine::Pcre2
        );
        assert_eq!(
            RegexEngine::from_str("vectorscan").expect("parse vectorscan"),
            RegexEngine::Vectorscan
        );
        assert_eq!(
            RegexEngine::from_str("vectorscan")
                .expect("parse vectorscan")
                .as_str(),
            "vectorscan"
        );
    }

    #[test]
    fn vectorscan_compatibility_catches_unsupported_constructs() {
        let issues = vectorscan_compatibility_issues(r"(?<=abc)(foo)\1");
        assert!(issues.iter().any(|issue| issue.contains("lookbehind")));
        assert!(issues.iter().any(|issue| issue.contains("backreferences")));
    }
}
