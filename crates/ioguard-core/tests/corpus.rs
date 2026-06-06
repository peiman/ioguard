use ioguard_core::{scan, ScanOptions, Verdict};
use std::path::PathBuf;

fn corpus_dir() -> PathBuf {
    // CARGO_MANIFEST_DIR is crates/ioguard-core; go up two levels to the workspace root.
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    PathBuf::from(manifest_dir).join("../../corpus")
}

#[test]
fn must_block_files_all_produce_block_verdict() {
    let must_block_dir = corpus_dir().join("must-block");
    let opts = ScanOptions::default();
    let mut checked = 0;

    for entry in std::fs::read_dir(&must_block_dir)
        .unwrap_or_else(|e| panic!("could not read {:?}: {e}", must_block_dir))
    {
        let entry = entry.expect("could not read dir entry");
        let path = entry.path();
        if path.extension().map(|e| e == "txt").unwrap_or(false) {
            let contents = std::fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("could not read {:?}: {e}", path));
            let result = scan(&contents, &opts);
            assert_eq!(
                result.verdict,
                Verdict::Block,
                "corpus/must-block/{} did not produce Block verdict (got {:?})",
                path.file_name().unwrap().to_string_lossy(),
                result.verdict
            );
            checked += 1;
        }
    }
    assert!(checked > 0, "no .txt files found in corpus/must-block/");
}

#[test]
fn must_allow_files_none_produce_block_verdict() {
    let must_allow_dir = corpus_dir().join("must-allow");
    let opts = ScanOptions::default();
    let mut checked = 0;

    for entry in std::fs::read_dir(&must_allow_dir)
        .unwrap_or_else(|e| panic!("could not read {:?}: {e}", must_allow_dir))
    {
        let entry = entry.expect("could not read dir entry");
        let path = entry.path();
        if path.extension().map(|e| e == "txt").unwrap_or(false) {
            let contents = std::fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("could not read {:?}: {e}", path));
            let result = scan(&contents, &opts);
            assert_ne!(
                result.verdict,
                Verdict::Block,
                "corpus/must-allow/{} produced Block verdict (should be allowed)",
                path.file_name().unwrap().to_string_lossy()
            );
            checked += 1;
        }
    }
    assert!(checked > 0, "no .txt files found in corpus/must-allow/");
}

// Runtime-constructed must-block test cases.
// These replace the deleted corpus/must-block/*.txt files that contained literal credential strings.
// Each input is constructed at runtime so no contiguous scannable secret appears in source.
#[cfg(test)]
mod runtime_must_block {
    use ioguard_core::{scan, ScanOptions, Verdict};

    fn assert_blocks(input: &str, label: &str) {
        let result = scan(input, &ScanOptions::default());
        assert_eq!(
            result.verdict,
            Verdict::Block,
            "runtime corpus case '{}' did not Block (got {:?})",
            label,
            result.verdict
        );
    }

    #[test]
    fn anthropic_key() {
        // Constructs an Anthropic API key (sk-ant-api03- prefix) embedded in prose
        let input = [
            "This message contains a secret: ",
            "sk-ant-",
            "api03-ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefg",
        ]
        .concat();
        assert_blocks(&input, "anthropic-key");
    }

    #[test]
    fn aws_key() {
        // Constructs an AWS access key (AKIA prefix + 16 chars)
        let input = ["AWS_ACCESS_KEY_ID=", "AKI", "AIOSFODNN7EXAMPLE"].concat();
        assert_blocks(&input, "aws-key");
    }

    #[test]
    fn aws_key_aroa() {
        // Constructs an AWS assumed-role key (AROA prefix + 16 chars)
        let input = ["ARO", "AIOSFODNN7EXAMPLE"].concat();
        assert_blocks(&input, "aws-key-aroa");
    }

    #[test]
    fn aws_key_asia() {
        // Constructs an AWS STS temporary key (ASIA prefix + 16 chars)
        let input = ["AWS_ACCESS_KEY_ID=", "ASI", "AIOSFODNN7EXAMPLE"].concat();
        assert_blocks(&input, "aws-key-asia");
    }

    #[test]
    fn github_oauth_token() {
        // Constructs a GitHub OAuth token (gho_ prefix)
        let input = ["gh", "o_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh1234"].concat();
        assert_blocks(&input, "github-oauth-token");
    }

    #[test]
    fn github_server_token() {
        // Constructs a GitHub server-to-server token (ghs_ prefix)
        let input = ["gh", "s_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh1234"].concat();
        assert_blocks(&input, "github-server-token");
    }

    #[test]
    fn github_fine_grained_pat() {
        // Constructs a GitHub fine-grained personal access token (github_pat_ prefix)
        let input = [
            "github_",
            "pat_11ABCDEFG0abcdefghijklmn_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefABCDEF",
        ]
        .concat();
        assert_blocks(&input, "github-fine-grained-pat");
    }

    #[test]
    fn gitlab_runner_auth_token() {
        // Constructs a GitLab runner authentication token (glrt- prefix)
        let input = ["gl", "rt-t1_abcdefghij1234567890"].concat();
        assert_blocks(&input, "gitlab-runner-auth-token");
    }

    #[test]
    fn gitlab_pat() {
        // Constructs a GitLab personal access token (glpat- prefix)
        let input = ["gl", "pat-abcdefghijklmnopqrst"].concat();
        assert_blocks(&input, "gitlab-pat");
    }

    #[test]
    fn gcp_api_key() {
        // Constructs a GCP API key (AIza prefix)
        let input = ["AI", "zaSyD-1234567890abcdefghijklmnopqrstuv"].concat();
        assert_blocks(&input, "gcp-api-key");
    }

    #[test]
    fn google_oauth_secret() {
        // Constructs a Google OAuth client secret (GOCSPX- prefix)
        let input = ["GOC", "SPX-abcdefghijklmnopqrstuvwxyz01"].concat();
        assert_blocks(&input, "google-oauth-secret");
    }

    #[test]
    fn gpg_armor_key() {
        // Constructs a GPG armored private key header
        let input = ["-----BEGIN PGP ", "PRIVATE KEY BLOCK-----"].concat();
        assert_blocks(&input, "gpg-armor-key");
    }

    #[test]
    fn openssh_private_key() {
        // Constructs an OpenSSH private key header
        let input = ["-----BEGIN OPENSSH ", "PRIVATE KEY-----"].concat();
        assert_blocks(&input, "openssh-private-key");
    }

    #[test]
    fn pem_mixed_case_label() {
        // Constructs a PEM private key header with mixed-case label
        let input = ["-----BEGIN Rsa ", "PRIVATE KEY-----"].concat();
        assert_blocks(&input, "pem-mixed-case-label");
    }

    #[test]
    fn sendgrid_api_key() {
        // Constructs a SendGrid API key (SG. prefix)
        let input = [
            "SG",
            ".abcdefghijklmnopqrstuv.abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJK",
        ]
        .concat();
        assert_blocks(&input, "sendgrid-api-key");
    }

    #[test]
    fn npm_access_token() {
        // Constructs an npm access token (npm_ prefix)
        let input = ["np", "m_abcdefghijklmnopqrstuvwxyz0123456789AB"].concat();
        assert_blocks(&input, "npm-access-token");
    }

    #[test]
    fn slack_bot_token() {
        // Constructs a Slack bot token (xoxb- prefix)
        let input = [
            "xox",
            "b-2401234567890-2412345678901-abcdEFGHijklMNOPqrstUVWX",
        ]
        .concat();
        assert_blocks(&input, "slack-bot-token");
    }

    #[test]
    fn slack_user_token() {
        // Constructs a Slack user token (xoxp- prefix)
        let input = [
            "xox",
            "p-2401234567890-2412345678901-abcdEFGHijklMNOPqrstUVWX",
        ]
        .concat();
        assert_blocks(&input, "slack-user-token");
    }

    #[test]
    fn slack_app_token() {
        // Constructs a Slack app-level token (xapp- prefix)
        let input = [
            "xap",
            "p-1-ABCDEFGHIJ-1234567890123-abcdefghijklmnopqrstuvwx",
        ]
        .concat();
        assert_blocks(&input, "slack-app-token");
    }

    #[test]
    fn slack_token_xoxa() {
        // Constructs a Slack workspace OAuth token (xoxa- prefix)
        let input = ["xox", "a-2-123456789012-abcdefghijklmnopqrst"].concat();
        assert_blocks(&input, "slack-token-xoxa");
    }

    #[test]
    fn slack_token_xoxr() {
        // Constructs a Slack OAuth refresh token (xoxr- prefix)
        let input = ["xox", "r-1234567890-abcdefghijklmnopqrstuvwxyz"].concat();
        assert_blocks(&input, "slack-token-xoxr");
    }

    #[test]
    fn slack_token_xoxs() {
        // Constructs a Slack legacy session token (xoxs- prefix)
        let input = ["xox", "s-987654321-abcdefghijklmnopqrstuvwxyz1234"].concat();
        assert_blocks(&input, "slack-token-xoxs");
    }

    #[test]
    fn stripe_restricted_key() {
        // Constructs a Stripe restricted key (rk_live_ prefix)
        let input = ["rk_", "live_abc123def456ghi789jkl012mnop"].concat();
        assert_blocks(&input, "stripe-restricted-key");
    }

    #[test]
    fn stripe_webhook_secret() {
        // Constructs a Stripe webhook secret (whsec_ prefix)
        let input = ["whs", "ec_abcdefghijklmnopqrstuvwxyz0123456789"].concat();
        assert_blocks(&input, "stripe-webhook-secret");
    }

    #[test]
    fn luhn_card() {
        // Constructs a Luhn-valid Visa test PAN embedded in prose (not in allowlist)
        let input = ["Please charge card 4111 1111 ", "1111 1111 for the amount."].concat();
        assert_blocks(&input, "luhn-card");
    }

    #[test]
    fn luhn_card_dotted() {
        // Constructs a Luhn-valid Visa test PAN with dot separators (not in allowlist)
        let input = [
            "Please charge card 4111.1111.",
            "1111.1111 for the full amount.",
        ]
        .concat();
        assert_blocks(&input, "luhn-card-dotted");
    }

    #[test]
    fn zero_width_keyword() {
        // Constructs text with U+200B ZERO WIDTH SPACE interleaved in "password"
        // The zero-width chars trigger the zero_width detector → Block verdict
        let input = [
            "Your p\u{200B}a\u{200B}s\u{200B}s\u{200B}",
            "w\u{200B}o\u{200B}r\u{200B}d is required.",
        ]
        .concat();
        assert_blocks(&input, "zero-width-keyword");
    }

    #[test]
    fn zero_width_word_joiner() {
        // Constructs an Anthropic-key-shaped prefix followed by chars interleaved with
        // U+2060 WORD JOINER. The zero-width format chars trigger the zero_width detector
        // → Block verdict.
        let suffix: String = "abcdefghij1234567890"
            .chars()
            .flat_map(|c| [c, '\u{2060}'])
            .collect();
        let input = ["sk-ant-", "api03-"].concat() + &suffix;
        assert_blocks(&input, "zero-width-word-joiner");
    }
}

// Runtime-constructed must-allow test cases.
// These replace the deleted corpus/must-allow/benign-private-key-banner.txt.
#[cfg(test)]
mod runtime_must_allow {
    use ioguard_core::{scan, ScanOptions, Verdict};

    #[test]
    fn benign_private_key_banner() {
        // Constructs a benign banner that mentions "PRIVATE KEY" but is not a real key header.
        // The PEM detector must not flag this (it has extra words after PRIVATE KEY).
        let input = [
            "-----BEGIN OUR COMPANY ",
            "PRIVATE KEY POLICY DOCUMENT-----",
        ]
        .concat();
        let result = scan(&input, &ScanOptions::default());
        assert_ne!(
            result.verdict,
            Verdict::Block,
            "benign-private-key-banner should not Block (got {:?})",
            result.verdict
        );
    }
}
