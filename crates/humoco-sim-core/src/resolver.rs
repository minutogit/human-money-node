use crate::types::Hash256;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NativeCandidateOrdering {
    /// Candidate A strictly takes precedence over Candidate B.
    PrecedenceA,
    /// Candidate B strictly takes precedence over Candidate A.
    PrecedenceB,
    /// Candidates are identical.
    Equal,
}

/// Pure comparison helper returning a total ordering from
/// `(confirmation class, H_canon, valid lock ID)` with explicit precedence semantics (A22-01).
///
/// Precedence rules:
/// 1. Higher confirmation class strictly takes precedence (DEC-064 / INV-0206).
/// 2. Smaller canonical hash takes precedence on equal classes (min(H_canon), Spec 02).
/// 3. Smaller lock ID takes precedence as secondary tie-breaker on equal primary hashes (A22-01).
pub fn compare_native_precedence(
    class_a: u8,
    h_a: &Hash256,
    id_a: &Hash256,
    class_b: u8,
    h_b: &Hash256,
    id_b: &Hash256,
) -> NativeCandidateOrdering {
    if id_a == id_b {
        return NativeCandidateOrdering::Equal;
    }
    if class_a > class_b {
        return NativeCandidateOrdering::PrecedenceA;
    }
    if class_b > class_a {
        return NativeCandidateOrdering::PrecedenceB;
    }
    if h_a < h_b {
        return NativeCandidateOrdering::PrecedenceA;
    }
    if h_b < h_a {
        return NativeCandidateOrdering::PrecedenceB;
    }
    if id_a < id_b {
        NativeCandidateOrdering::PrecedenceA
    } else {
        NativeCandidateOrdering::PrecedenceB
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compare_native_precedence() {
        let h1 = [1u8; 32];
        let h2 = [2u8; 32];
        let id1 = [10u8; 32];
        let id2 = [20u8; 32];

        assert_eq!(
            compare_native_precedence(2, &h2, &id2, 1, &h1, &id1),
            NativeCandidateOrdering::PrecedenceA
        );
        assert_eq!(
            compare_native_precedence(1, &h1, &id1, 2, &h2, &id2),
            NativeCandidateOrdering::PrecedenceB
        );
        assert_eq!(
            compare_native_precedence(1, &h1, &id1, 1, &h2, &id2),
            NativeCandidateOrdering::PrecedenceA
        );
        assert_eq!(
            compare_native_precedence(1, &h1, &id1, 1, &h1, &id1),
            NativeCandidateOrdering::Equal
        );
    }
}
