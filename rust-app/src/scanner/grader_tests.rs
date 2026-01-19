#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_grader_perfect_score() {
        // A perfect site might have some +5 modifiers, but max is 100.
        // Or if empty results -> 100 by default (start).
        let results = vec![];
        let (score, grade) = Grader::grade(&results);
        assert_eq!(score, 100);
        assert_eq!(grade, Grade::APlus);
    }

    #[test]
    fn test_grader_flawed_score() {
        // Start 100
        // CspNotImplemented: -25
        // HstsNotImplemented: -20
        // Total: 55 -> Grade C
        let results = vec![
            TestResult::CspNotImplemented,
            TestResult::HstsNotImplemented,
        ];
        let (score, grade) = Grader::grade(&results);
        assert_eq!(score, 55);
        assert_eq!(grade, Grade::C);
    }

    #[test]
    fn test_grader_clamping() {
        // Start 100
        // Penalty: -120
        // Result: -20 -> Clamped to 0 -> F
        let results = vec![
             TestResult::CspNotImplemented, // -25
             TestResult::HstsNotImplemented, // -20
             TestResult::RedirectionMissing, // -20
             TestResult::CookiesSessionWithoutSecureFlag, // -40
             TestResult::ReferrerPolicyHeaderInvalid, // -5
             TestResult::XFrameOptionsNotImplemented // -20
             // Total: -130
        ];
        let (score, grade) = Grader::grade(&results);
        assert_eq!(score, 0);
        assert_eq!(grade, Grade::F);
    }
}
