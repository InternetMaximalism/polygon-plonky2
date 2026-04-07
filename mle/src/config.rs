/// Configuration for the MLE proving system.

/// WHIR PCS configuration parameters.
#[derive(Clone, Debug)]
pub struct WhirConfig {
    /// Log-inverse of the Reed-Solomon code rate.
    /// rate = 1 / 2^rate_bits.
    /// Higher values mean more redundancy (larger codeword) but better soundness.
    pub rate_bits: usize,

    /// Number of query rounds for the proximity test.
    pub num_queries: usize,

    /// Security parameter in bits.
    pub security_bits: usize,

    /// Proof-of-work difficulty bits (grinding).
    pub pow_bits: usize,

    /// Folding factor per round (log2).
    pub folding_factor: usize,
}

impl WhirConfig {
    /// Default WHIR configuration with rate = 1/16 (rate_bits = 4).
    ///
    /// This gives a code rate of 1/16, meaning each codeword is 16x the message length.
    /// Combined with 90-bit security target and appropriate query count.
    pub fn default_rate_16() -> Self {
        Self {
            rate_bits: 4,       // rate = 1/2^4 = 1/16
            num_queries: 28,    // Sufficient for 90-bit security at rate 1/16
            security_bits: 90,
            pow_bits: 0,
            folding_factor: 4,  // Fold by 2^4 = 16 per round
        }
    }

    /// The code rate as a fraction 1/2^rate_bits.
    pub fn inv_rate(&self) -> usize {
        1 << self.rate_bits
    }

    /// Estimated proof size in field elements for n-variable polynomial.
    ///
    /// WHIR proof size is approximately:
    ///   O(num_queries * (rate_bits + n/folding_factor) * inv_rate)
    /// This is polylogarithmic in 2^n when folding_factor > 1.
    pub fn estimated_proof_field_elements(&self, num_vars: usize) -> usize {
        let num_rounds = (num_vars + self.folding_factor - 1) / self.folding_factor;
        // Each round: num_queries Merkle paths of depth ~(rate_bits + folding_factor)
        // Plus round messages
        self.num_queries * (self.rate_bits + self.folding_factor) * num_rounds
            + num_rounds * (1 << self.folding_factor)
    }
}

impl Default for WhirConfig {
    fn default() -> Self {
        Self::default_rate_16()
    }
}

/// Full MLE prover/verifier configuration.
#[derive(Clone, Debug)]
pub struct MleConfig {
    /// WHIR PCS parameters.
    pub whir: WhirConfig,

    /// Maximum constraint degree per sumcheck variable.
    /// Automatically detected from gate set if None.
    pub max_constraint_degree: Option<usize>,
}

impl Default for MleConfig {
    fn default() -> Self {
        Self {
            whir: WhirConfig::default(),
            max_constraint_degree: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = WhirConfig::default();
        assert_eq!(config.rate_bits, 4);
        assert_eq!(config.inv_rate(), 16);
        assert_eq!(config.security_bits, 90);
    }

    #[test]
    fn test_proof_size_estimate() {
        let config = WhirConfig::default_rate_16();
        // For a circuit with 2^16 gates (n=16)
        let size = config.estimated_proof_field_elements(16);
        // Should be much smaller than 2^16 = 65536
        assert!(size < 65536, "Proof size {} should be sublinear", size);
    }
}
