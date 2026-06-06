use crate::types::{Finding, ScanOptions};

pub mod bidi;
pub mod homoglyph;
pub mod luhn;
pub mod secret;
pub mod special_token;
pub mod unicode_tags;
pub mod zero_width;

/// The trait all detectors implement.
pub trait Detector {
    fn detect(&self, text: &str, opts: &ScanOptions) -> Vec<Finding>;
}
