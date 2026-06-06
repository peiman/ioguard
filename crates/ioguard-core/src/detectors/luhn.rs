/// Validate a string of digits using the Luhn algorithm.
///
/// The caller must strip spaces/dashes before calling. Returns true if
/// the checksum is valid (sum % 10 == 0).
///
/// Algorithm: starting from the rightmost digit, double every second digit.
/// If doubling produces > 9, subtract 9. Sum all digits. Valid if sum % 10 == 0.
pub fn is_valid_luhn(digits: &str) -> bool {
    if digits.is_empty() {
        return false;
    }
    let mut sum: u32 = 0;
    let mut double = false;
    for ch in digits.chars().rev() {
        let Some(d) = ch.to_digit(10) else {
            return false;
        };
        let value = if double {
            let doubled = d * 2;
            if doubled > 9 {
                doubled - 9
            } else {
                doubled
            }
        } else {
            d
        };
        sum += value;
        double = !double;
    }
    sum.is_multiple_of(10)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stripe_test_card_is_luhn_valid() {
        assert!(is_valid_luhn("4242424242424242"));
    }

    #[test]
    fn amex_test_card_is_luhn_valid() {
        assert!(is_valid_luhn("378282246310005"));
    }

    #[test]
    fn random_invalid_is_not_luhn_valid() {
        assert!(!is_valid_luhn("1234567890123456"));
    }

    #[test]
    fn all_zeros_is_luhn_valid() {
        assert!(is_valid_luhn("0000000000000000"));
    }

    #[test]
    fn visa_test_card_is_luhn_valid() {
        assert!(is_valid_luhn("4111111111111111"));
    }

    #[test]
    fn empty_string_is_not_valid() {
        assert!(!is_valid_luhn(""));
    }

    #[test]
    fn non_digit_char_is_not_valid() {
        assert!(!is_valid_luhn("4111-1111-1111-1111"));
    }
}
