//! Exact integer mirror of HunterMiningCore._effectiveTarget.
use proof_core::{Target, Uint256};
pub const BASE_WAD: u64 = 1_000_000_000_000_000_000;
pub const MAX_WAD: u64 = 3_000_000_000_000_000_000;

pub fn effective_target(
    base: Target,
    multiplier: Uint256,
    maximum: Uint256,
) -> Result<Target, String> {
    if multiplier <= Uint256::from(BASE_WAD) {
        return Ok(base);
    }
    let bounded = multiplier.min(Uint256::from(MAX_WAD)).to_be_bytes();
    let mult = u64::from_be_bytes(
        bounded[24..]
            .try_into()
            .expect("bounded multiplier fits u64"),
    );
    if base.to_be_bytes() > maximum.to_be_bytes() {
        return Err("base target exceeds MiningCore.MAX_TARGET".to_owned());
    }
    // Solidity deliberately saturates at floor(MAX_TARGET * WAD / mult),
    // including its rounding boundary; do not substitute simple min(base*mult/WAD).
    let max_safe = mul_div(maximum.to_be_bytes(), BASE_WAD, mult)?;
    let widened = if base.to_be_bytes() >= max_safe {
        maximum.to_be_bytes()
    } else {
        mul_div(base.to_be_bytes(), mult, BASE_WAD)?
    };
    Ok(Target::from_be_bytes(widened.min(maximum.to_be_bytes())))
}

// A 320-bit temporary holds uint256 * uint64 without truncation. Long division
// keeps a remainder smaller than a uint64; both inner operations fit in u128.
fn mul_div(value: [u8; 32], factor: u64, divisor: u64) -> Result<[u8; 32], String> {
    let mut wide = [0_u8; 40];
    let mut carry = 0_u128;
    for i in (0..32).rev() {
        let product = u128::from(value[i]) * u128::from(factor) + carry;
        wide[i + 8] = product as u8;
        carry = product >> 8;
    }
    wide[..8].copy_from_slice(&(carry as u64).to_be_bytes());
    let mut remainder = 0_u128;
    for byte in &mut wide {
        let partial = (remainder << 8) | u128::from(*byte);
        *byte = (partial / u128::from(divisor)) as u8;
        remainder = partial % u128::from(divisor);
    }
    if wide[..8].iter().any(|byte| *byte != 0) {
        return Err("effective target exceeds uint256".to_owned());
    }
    Ok(wide[8..].try_into().expect("uint256 suffix"))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn target(n: u64) -> Target {
        Target::from_be_bytes(Uint256::from(n).to_be_bytes())
    }
    #[test]
    fn base_fractional_cap_and_solidity_rounding_boundary() {
        for mult in [0, BASE_WAD - 1, BASE_WAD] {
            assert_eq!(
                effective_target(target(19), Uint256::from(mult), Uint256::from(100_u64)).unwrap(),
                target(19)
            );
        }
        assert_eq!(
            effective_target(
                target(19),
                Uint256::from(BASE_WAD * 3 / 2),
                Uint256::from(100_u64)
            )
            .unwrap(),
            target(28)
        );
        assert_eq!(
            effective_target(target(20), Uint256::from(u64::MAX), Uint256::from(100_u64)).unwrap(),
            target(60)
        );
        assert_eq!(
            effective_target(target(33), Uint256::from(MAX_WAD), Uint256::from(100_u64)).unwrap(),
            target(100)
        );
        assert_eq!(
            effective_target(target(32), Uint256::from(MAX_WAD), Uint256::from(100_u64)).unwrap(),
            target(96)
        );
    }
    #[test]
    fn full_width_multiplication_does_not_wrap() {
        let max = Uint256::from_be_bytes([255; 32]);
        assert_eq!(mul_div([255; 32], BASE_WAD, BASE_WAD).unwrap(), [255; 32]);
        assert_eq!(
            effective_target(Target::from_be_bytes([255; 32]), max, max).unwrap(),
            Target::from_be_bytes([255; 32])
        );
        let mut base = [255; 32];
        base[0] = 0x1f;
        let mut expected = [255; 32];
        expected[0] = 0x5f;
        expected[31] = 0xfd;
        assert_eq!(
            effective_target(Target::from_be_bytes(base), max, max).unwrap(),
            Target::from_be_bytes(expected)
        );
    }
}
