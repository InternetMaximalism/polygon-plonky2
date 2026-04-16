# EqPolyLib.sol — Soundness Report

NO_ISSUES_FOUND

The eq evaluation is algebraically correct:
- factor = 2·τ_j·r_j - τ_j - r_j + 1 is the correct simplified form of τ_j·r_j + (1-τ_j)(1-r_j)
- The computation uses addmod/mulmod with P throughout
- sub(p, t_j) is safe because t_j < P (validated at input)
- The product accumulation is correct
- Bit ordering (variable j corresponds to array index j) matches the Rust convention
