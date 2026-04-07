/// WHIR-based multilinear polynomial commitment scheme.
///
/// Integrates the `whir` crate (arkworks-based) with the plonky2_mle
/// proving system via the `MultilinearPCS` trait.
///
/// Field conversion: plonky2's GoldilocksField (u64 repr) ↔ arkworks
/// Field64 (Montgomery repr) via canonical u64 serialization.
use ark_ff::{Field as ArkField, PrimeField as ArkPrimeField};
use plonky2_field::types::{Field, PrimeField64};

use crate::dense_mle::DenseMultilinearExtension;
use crate::transcript::Transcript;

// Re-export whir's Goldilocks field type
pub use whir::algebra::fields::{Field64 as ArkGoldilocks, Field64_2 as ArkGoldilocks2};

/// Convert a plonky2 GoldilocksField element to arkworks Field64.
pub fn plonky2_to_ark(val: plonky2_field::goldilocks_field::GoldilocksField) -> ArkGoldilocks {
    ArkGoldilocks::from(val.to_canonical_u64())
}

/// Convert an arkworks Field64 element to plonky2 GoldilocksField.
pub fn ark_to_plonky2(val: ArkGoldilocks) -> plonky2_field::goldilocks_field::GoldilocksField {
    let repr: u64 = val.into_bigint().0[0];
    plonky2_field::goldilocks_field::GoldilocksField::from_canonical_u64(repr)
}

/// Convert a vector of plonky2 field elements to arkworks.
pub fn plonky2_vec_to_ark(
    vals: &[plonky2_field::goldilocks_field::GoldilocksField],
) -> Vec<ArkGoldilocks> {
    vals.iter().map(|v| plonky2_to_ark(*v)).collect()
}

/// Convert a vector of arkworks field elements to plonky2.
pub fn ark_vec_to_plonky2(
    vals: &[ArkGoldilocks],
) -> Vec<plonky2_field::goldilocks_field::GoldilocksField> {
    vals.iter().map(|v| ark_to_plonky2(*v)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use plonky2_field::goldilocks_field::GoldilocksField;
    use plonky2_field::types::Field;

    #[test]
    fn test_field_conversion_roundtrip() {
        // Test small values
        for i in 0..100u64 {
            let p2 = GoldilocksField::from_canonical_u64(i);
            let ark = plonky2_to_ark(p2);
            let back = ark_to_plonky2(ark);
            assert_eq!(p2, back, "Roundtrip failed for {i}");
        }

        // Test large values near P
        let p = 0xFFFFFFFF00000001u64;
        for offset in [0u64, 1, 2, 100, 1000, 1 << 32, 1 << 53, p - 2, p - 1] {
            let val = offset.min(p - 1);
            let p2 = GoldilocksField::from_canonical_u64(val);
            let ark = plonky2_to_ark(p2);
            let back = ark_to_plonky2(ark);
            assert_eq!(p2, back, "Roundtrip failed for val={val}");
        }
    }

    #[test]
    fn test_field_arithmetic_consistency() {
        // Verify that addition/multiplication produce the same results in both fields
        let a_p2 = GoldilocksField::from_canonical_u64(123456789);
        let b_p2 = GoldilocksField::from_canonical_u64(987654321);

        let a_ark = plonky2_to_ark(a_p2);
        let b_ark = plonky2_to_ark(b_p2);

        // Addition
        let sum_p2 = a_p2 + b_p2;
        let sum_ark = a_ark + b_ark;
        assert_eq!(sum_p2, ark_to_plonky2(sum_ark), "Addition mismatch");

        // Multiplication
        let prod_p2 = a_p2 * b_p2;
        let prod_ark = a_ark * b_ark;
        assert_eq!(prod_p2, ark_to_plonky2(prod_ark), "Multiplication mismatch");

        // Inversion
        let inv_p2 = a_p2.inverse();
        let inv_ark = a_ark.inverse().unwrap();
        assert_eq!(inv_p2, ark_to_plonky2(inv_ark), "Inversion mismatch");
    }
}
