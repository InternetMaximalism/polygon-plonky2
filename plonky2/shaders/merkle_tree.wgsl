@group(0) @binding(0) var<storage, read_write> input: array<P1HashDigest>;
@group(0) @binding(1) var<storage, read_write> nodes: array<P1HashDigest>;
@group(0) @binding(2) var<storage, read_write> cap: array<P1HashDigest>;
@group(0) @binding(3) var<storage, read> args: MerkleTreeKernelArgs;
@group(0) @binding(4) var<storage, read> mdsCirc: array<BigInt, 12>;
@group(0) @binding(5) var<storage, read> mdsDiag: array<BigInt, 12>;
@group(0) @binding(6) var<storage, read> rc: array<BigInt, 360>;

const WORKGROUP_SIZE: u32 = 64u;
const WORKGROUP_SIZE_Y: u32 = 1u;
var<private> carry_flag: u32 = 0u;
const M: BigInt = BigInt(array(u32(1), u32(4294967295)));
const MontyOne: BigInt = BigInt(array(u32(4294967295), u32(0)));
const PP1D2: BigInt = BigInt(array(u32(2147483649), u32(2147483647)));
const M0NInv: u32 = 4294967295;
const R2modP: BigInt = BigInt(array(u32(1), u32(4294967294)));

struct BigInt {
  limbs: array<u32, 2>,
};
struct P1HashDigest {
  elems: array<BigInt, 4>,
};
struct MerkleTreeKernelArgs {
  capLen: u32,
  layer: u32,
  srcLayerSize: u32,
  dstLayerSize: u32,
  srcOffset: u32,
  dstOffset: u32,
  writeToCap: i32,
};

@compute @workgroup_size(WORKGROUP_SIZE, WORKGROUP_SIZE_Y)
fn processMerkleTreeLayerWithCap(@builtin(local_invocation_id)  local_id : vec3<u32>,      // ≈ CUDA threadIdx
@builtin(workgroup_id)         workgroup_id: vec3<u32>,   // ≈ CUDA blockIdx
@builtin(num_workgroups)       num_workgroups: vec3<u32>, // ≈ CUDA gridDim
@builtin(global_invocation_id) global_id: vec3<u32>,      // = workgroup_id * workgroup_size + local_id
) {
  /* Process a single layer of the Merkle tree with cap support using
the layer-based storage layout shared with the proof generator.

TODO: In theory there's no reason to differentiate between the cap and
the nodes. The cap is just the last N nodes. We can precompute the indices
at which the cap is located and handle copying back the correct nodes
as part of the Nim (CPU) routine that copies the results back. */;
  let grid_width: u32 = (num_workgroups.x * 64u);
  let tid: u32 = ((u32(global_id.y) * u32(grid_width)) + u32(global_id.x));
  if ((args.dstLayerSize <= tid)) {
    return ;
  };
  let leftIdx: u32 = (tid * 2u);
  let rightIdx: u32 = (leftIdx + 1u);
  var state: array<BigInt, 12>;

  { // unrolledIter_i0
  setZero_lmut((&state[0]));
  } // unrolledIter_i0


  { // unrolledIter_i1
  setZero_lmut((&state[1]));
  } // unrolledIter_i1


  { // unrolledIter_i2
  setZero_lmut((&state[2]));
  } // unrolledIter_i2


  { // unrolledIter_i3
  setZero_lmut((&state[3]));
  } // unrolledIter_i3


  { // unrolledIter_i4
  setZero_lmut((&state[4]));
  } // unrolledIter_i4


  { // unrolledIter_i5
  setZero_lmut((&state[5]));
  } // unrolledIter_i5


  { // unrolledIter_i6
  setZero_lmut((&state[6]));
  } // unrolledIter_i6


  { // unrolledIter_i7
  setZero_lmut((&state[7]));
  } // unrolledIter_i7


  { // unrolledIter_i8
  setZero_lmut((&state[8]));
  } // unrolledIter_i8


  { // unrolledIter_i9
  setZero_lmut((&state[9]));
  } // unrolledIter_i9


  { // unrolledIter_i10
  setZero_lmut((&state[10]));
  } // unrolledIter_i10


  { // unrolledIter_i11
  setZero_lmut((&state[11]));
  } // unrolledIter_i11

  if ((args.layer == 0u)) {
    writeData_lmut_l_smut_l((&state), 0, (&input), leftIdx);
    if ((rightIdx < args.srcLayerSize)) {
      writeData_lmut_l_smut_l((&state), 4, (&input), rightIdx);
    };
  } else {
    writeData_lmut_l_smut_l((&state), 0, (&nodes), (args.srcOffset + leftIdx));
    if ((rightIdx < args.srcLayerSize)) {
      writeData_lmut_l_smut_l((&state), 4, (&nodes), (args.srcOffset + rightIdx));
    };
  };
  poseidonPermuteMutImpl_lmut((&state));
  if ((args.writeToCap == 1)) {
    if ((tid < args.capLen)) {

      { // unrolledIter_i0
      cap[tid].elems[0] = getCanonical(state[0]);
      } // unrolledIter_i0


      { // unrolledIter_i1
      cap[tid].elems[1] = getCanonical(state[1]);
      } // unrolledIter_i1


      { // unrolledIter_i2
      cap[tid].elems[2] = getCanonical(state[2]);
      } // unrolledIter_i2


      { // unrolledIter_i3
      cap[tid].elems[3] = getCanonical(state[3]);
      } // unrolledIter_i3

    };
  } else {

    { // unrolledIter_i0
    nodes[(args.dstOffset + tid)].elems[0] = state[0];
    } // unrolledIter_i0


    { // unrolledIter_i1
    nodes[(args.dstOffset + tid)].elems[1] = state[1];
    } // unrolledIter_i1


    { // unrolledIter_i2
    nodes[(args.dstOffset + tid)].elems[2] = state[2];
    } // unrolledIter_i2


    { // unrolledIter_i3
    nodes[(args.dstOffset + tid)].elems[3] = state[3];
    } // unrolledIter_i3

  };
}

fn setZero_lmut(a: ptr<function, BigInt>) {
  /* Sets all limbs of the field element to zero in place */;
  for(var i: u32 = 0u; i < 2; i++) {
    (*a).limbs[i] = 0u;
  };
}

fn writeData_lmut_l_smut_l(dst: ptr<function, array<BigInt, 12>>, dstOffset: u32, data: ptr<storage, array<P1HashDigest>, read_write>, srcOffset: u32) {
  /* Writes all elements from `data` at `srcOffset` to `dstOffset` in `state`. */;

  { // unrolledIter_i0
  (*dst)[(dstOffset + u32(0))] = (*data)[srcOffset].elems[0];
  } // unrolledIter_i0


  { // unrolledIter_i1
  (*dst)[(dstOffset + u32(1))] = (*data)[srcOffset].elems[1];
  } // unrolledIter_i1


  { // unrolledIter_i2
  (*dst)[(dstOffset + u32(2))] = (*data)[srcOffset].elems[2];
  } // unrolledIter_i2


  { // unrolledIter_i3
  (*dst)[(dstOffset + u32(3))] = (*data)[srcOffset].elems[3];
  } // unrolledIter_i3

}

fn poseidonPermuteMutImpl_lmut(state: ptr<function, array<BigInt, 12>>) {
  /* Main Poseidon permutation - inlined for performance */;
  var roundCtr: u32 = 0;
  fullRounds_lmut_lmut(state, (&roundCtr));
  partialRoundsNaive_lmut_lmut(state, (&roundCtr));
  fullRounds_lmut_lmut(state, (&roundCtr));
}

fn fullRounds_lmut_lmut(state: ptr<function, array<BigInt, 12>>, round_ctr: ptr<function, u32>) {
  for(var i: u32 = 0; i < 4u; i++) {
    constantLayer_lmut_lmut(state, round_ctr);
    sboxLayer_lmut(state);
    mdsLayer_lmut(state);
    (*round_ctr) = ((*round_ctr) + 1u);
  };
}

fn constantLayer_lmut_lmut(state: ptr<function, array<BigInt, 12>>, round_ctr: ptr<function, u32>) {
  for(var i: u32 = 0; i < 12; i++) {
    let round_constant: BigInt = rc[(i + (12u * (*round_ctr)))];
    /* XXX: add canonical u64?
-> Need to construct Montgomery? We just need to turn round constants into
Montgomery before! */;
    add_lmut_l_l((&(*state)[i]), (*state)[i], round_constant);
  };
}

fn add_lmut_l_l(r: ptr<function, BigInt>, a: BigInt, b: BigInt) {
  /* Addition of two finite field elements stored in `a` and `b`.
The result is stored in `r`. */;
  (*r) = modadd(a, b, M);
}

fn modadd(a: BigInt, b: BigInt, M: BigInt) -> BigInt {
  /* Generate an optimized modular addition kernel
with parameters `a, b, modulus: Limbs -> Limbs` */;
  var t: BigInt = BigInt(array<u32, 2>());
  t.limbs[0] = add_co(a.limbs[0], b.limbs[0]);

  { // unrolledIter_i1
  t.limbs[1] = add_cio(a.limbs[1], b.limbs[1]);
  } // unrolledIter_i1

  let overflowedLimbs: u32 = add_ci(0u, 0u);
  t = finalSubMayOverflow(t, M, overflowedLimbs);
  return t;
}

fn add_co(a: u32, b: u32) -> u32 {
  let result: u32 = (a + b);
  carry_flag = select(0u, 1u, (result < a));
  return result;
}

fn add_cio(a: u32, b: u32) -> u32 {
  let temp: u32 = (a + b);
  let result: u32 = (temp + carry_flag);
  carry_flag = select(0u, 1u, ((temp < a) || (result < temp)));
  return result;
}

fn add_ci(a: u32, b: u32) -> u32 {
  let temp: u32 = (a + b);
  let result: u32 = (temp + carry_flag);
  return result;
}

fn finalSubMayOverflow(a: BigInt, M: BigInt, overflowedLimbs: u32) -> BigInt {
  /* If a >= Modulus: r <- a-M
else:            r <- a

This is constant-time straightline code.
Due to warp divergence, the overhead of doing comparison with shortcutting might not be worth it on GPU.

To be used when the final substraction can
also overflow the limbs (a 2^256 order of magnitude modulus stored in n words of total max size 2^256) */;
  var scratch: BigInt = BigInt(array<u32, 2>());
  scratch.limbs[0] = sub_bo(a.limbs[0], M.limbs[0]);

  { // unrolledIter_i1
  scratch.limbs[1] = sub_bio(a.limbs[1], M.limbs[1]);
  } // unrolledIter_i1

  let underflowedModulus: u32 = sub_bi(overflowedLimbs, 0u);
  var r: BigInt = BigInt(array<u32, 2>());

  { // unrolledIter_i0
  r.limbs[0] = slct(scratch.limbs[0], a.limbs[0], bitcast<i32>(underflowedModulus));
  } // unrolledIter_i0


  { // unrolledIter_i1
  r.limbs[1] = slct(scratch.limbs[1], a.limbs[1], bitcast<i32>(underflowedModulus));
  } // unrolledIter_i1

  return r;
}

fn sub_bo(a: u32, b: u32) -> u32 {
  let result: u32 = (a - b);
  carry_flag = select(0u, 1u, (a < b));
  return result;
}

fn sub_bio(a: u32, b: u32) -> u32 {
  let temp: u32 = (a - b);
  let result: u32 = (temp - carry_flag);
  carry_flag = select(0u, 1u, ((a < b) || (temp < carry_flag)));
  return result;
}

fn sub_bi(a: u32, b: u32) -> u32 {
  let temp: u32 = (a - b);
  let result: u32 = (temp - carry_flag);
  return result;
}

fn slct(a: u32, b: u32, pred: i32) -> u32 {
  return select(b, a, (0 <= pred));
}

fn sboxLayer_lmut(state: ptr<function, array<BigInt, 12>>) {
  for(var i: u32 = 0; i < 12; i++) {
    (*state)[i] = sboxMonomial((*state)[i]);
  };
}

fn sboxMonomial(x: BigInt) -> BigInt {
  var x2: BigInt;
  var x3: BigInt;
  var x4: BigInt;
  mul_lmut_l_l((&x2), x, x);
  mul_lmut_l_l((&x4), x2, x2);
  mul_lmut_l_l((&x3), x, x2);
  mul_lmut_l_l((&x2), x3, x4);
  return x2;
}

fn mul_lmut_l_l(r: ptr<function, BigInt>, a: BigInt, b: BigInt) {
  /* Multiplication of two finite field elements stored in `a` and `b`.
The result is stored in `r`. */;
  (*r) = mtymul_FIPS___f4FuSyv5EILd5KB2IIWyig(a, b, M, false);
}

fn mtymul_FIPS___f4FuSyv5EILd5KB2IIWyig(a: BigInt, b: BigInt, M: BigInt, lazyReduce: bool) -> BigInt {
  /* Montgomery Multiplication using Finely Integrated Product Scanning (FIPS).
This implementation can be used for fields that do not have any spare bits.

This maps
- [0, 2p) -> [0, 2p) with lazyReduce
- [0, 2p) -> [0, p) without

lazyReduce skips the final substraction step. */;
;
  var z: BigInt = BigInt(array<u32, 2>());
  const L: i32 = 2;
  var t: u32 = 0u;
  var u: u32 = 0u;
  var v: u32 = 0u;

  { // unrolledIter_i0

  mulAcc_lmut_lmut_lmut_l_l((&t), (&u), (&v), a.limbs[0], b.limbs[0]);
  z.limbs[0] = (v * 4294967295u);
  mulAcc_lmut_lmut_lmut_l_l((&t), (&u), (&v), z.limbs[0], M.limbs[0]);
  v = u;
  u = t;
  t = 0u;
  } // unrolledIter_i0


  { // unrolledIter_i1

  { // unrolledIter_j0
  mulAcc_lmut_lmut_lmut_l_l((&t), (&u), (&v), a.limbs[0], b.limbs[1]);
  mulAcc_lmut_lmut_lmut_l_l((&t), (&u), (&v), z.limbs[0], M.limbs[1]);
  } // unrolledIter_j0

  mulAcc_lmut_lmut_lmut_l_l((&t), (&u), (&v), a.limbs[1], b.limbs[0]);
  z.limbs[1] = (v * 4294967295u);
  mulAcc_lmut_lmut_lmut_l_l((&t), (&u), (&v), z.limbs[1], M.limbs[0]);
  v = u;
  u = t;
  t = 0u;
  } // unrolledIter_i1


  { // unrolledIter_i2

  { // unrolledIter_j1
  mulAcc_lmut_lmut_lmut_l_l((&t), (&u), (&v), a.limbs[1], b.limbs[1]);
  mulAcc_lmut_lmut_lmut_l_l((&t), (&u), (&v), z.limbs[1], M.limbs[1]);
  } // unrolledIter_j1

  z.limbs[0] = v;
  v = u;
  u = t;
  t = 0u;
  } // unrolledIter_i2


  { // unrolledIter_i3

  z.limbs[1] = v;
  v = u;
  u = t;
  t = 0u;
  } // unrolledIter_i3

  let cond: bool = (!(v == 0u) || !less(z, M));
  csub_no_mod_lmut_l_l((&z), M, cond);
  return z;
}

fn mulAcc_lmut_lmut_lmut_l_l(t: ptr<function, u32>, u: ptr<function, u32>, v: ptr<function, u32>, a: u32, b: u32) {
  /* (t, u, v) <- (t, u, v) + a * b */;
  (*v) = mulloadd_co(a, b, (*v));
  (*u) = mulhiadd_cio(a, b, (*u));
  (*t) = add_ci((*t), 0u);
}

fn mulloadd_co(a: u32, b: u32, c: u32) -> u32 {
  /* Multiply-add low with carry out */;
  let product: u32 = mul_lo(a, b);
  return add_co(product, c);
}

fn mul_lo(a: u32, b: u32) -> u32 {
  /* Returns the lower 32 bit of the uint32 multiplication
Native WGSL multiplication automatically wraps to 32 bits */;
  return (a * b);
}

fn mulhiadd_cio(a: u32, b: u32, c: u32) -> u32 {
  /* Multiply-add high with carry in and carry out */;
  let hi_product: u32 = mul_hi(a, b);
  return add_cio(hi_product, c);
}

fn mul_hi(a: u32, b: u32) -> u32 {
  /* Returns the upper 32 bit of the uint32 multiplication
Decompose into 16-bit chunks to avoid overflow */;
  let a_lo: u32 = (a & 65535u);
  let a_hi: u32 = (a >> 16);
  let b_lo: u32 = (b & 65535u);
  let b_hi: u32 = (b >> 16);
  let p0: u32 = (a_lo * b_lo);
  let p1: u32 = (a_lo * b_hi);
  let p2: u32 = (a_hi * b_lo);
  let p3: u32 = (a_hi * b_hi);
  let middle: u32 = (((p0 >> 16) + (p1 & 65535u)) + (p2 & 65535u));
  let carry: u32 = (middle >> 16);
  return (((p3 + (p1 >> 16)) + (p2 >> 16)) + carry);
}

fn less(a: BigInt, b: BigInt) -> bool {
  /* Returns true if a < b for two big ints in *canonical*
representation.

NOTE: The inputs are compared *as is*. That means if they are
in Montgomery representation the result will not reflect the
ordering relation of their associated canonical values!
Call `toCanonical` on field elements in Montgomery order before
comparing them.

Comparison is constant-time */;
  var borrow: u32;
  sub_bo(a.limbs[0], b.limbs[0]);

  { // unrolledIter_i1
  sub_bio(a.limbs[1], b.limbs[1]);
  } // unrolledIter_i1

  borrow = sub_bi(0u, 0u);
  return bool(borrow);
}

fn csub_no_mod_lmut_l_l(r: ptr<function, BigInt>, a: BigInt, condition: bool) {
  /* Conditionally subtract `a` from `r` in place *without* modular
reduction.

Note: This is constant-time */;
  var t: BigInt = BigInt(array<u32, 2>());
  sub_no_mod___d9cpFFTTlwIJez0po9bQ0J4g_lmut_l_l((&t), (*r), a);
  ccopy___HjzYt6G86OUE1KbkDccyqg_lmut_l_l(r, t, condition);
}

fn sub_no_mod___d9cpFFTTlwIJez0po9bQ0J4g_lmut_l_l(r: ptr<function, BigInt>, a: BigInt, b: BigInt) {
  /* Subtraction of two finite field elements stored in `a` and `b`
*without* modular reduction.
The result is stored in `r`. */;
  (*r) = sub_no_mod(a, b);
}

fn sub_no_mod(a: BigInt, b: BigInt) -> BigInt {
  /* Generate an optimized substraction kernel
with parameters `a, b, modulus: Limbs -> Limbs`
I.e. this does _not_ perform modular reduction. */;
  var t: BigInt = BigInt(array<u32, 2>());
  t.limbs[0] = sub_bo(a.limbs[0], b.limbs[0]);

  { // unrolledIter_i1
  t.limbs[1] = sub_bio(a.limbs[1], b.limbs[1]);
  } // unrolledIter_i1

  return t;
}

fn ccopy___HjzYt6G86OUE1KbkDccyqg_lmut_l_l(a: ptr<function, BigInt>, b: BigInt, condition: bool) {
  /* Conditional copy.
If condition is true: b is copied into a
If condition is false: a is left unmodified

Note: This is constant-time */;
  /* XXX: add support for `IfExpr`! Requires though. */;
  var cond: i32;
  if (condition) {
    cond = 1;
  } else {
    cond = -1;
  };
  for(var i: u32 = 0u; i < 2; i++) {
    (*a).limbs[i] = slct(b.limbs[i], (*a).limbs[i], cond);
  };
}

fn mdsLayer_lmut(state: ptr<function, array<BigInt, 12>>) {
  /* XXX: Return copy? Better mutate in place?
XXX: We could consider an implementation closer to the regular implementation
Plonky2 uses for generic fields. But that requires us to implement a `u128` type
with _at least_ multiplication. */;
  var tmp: array<BigInt, 12>;
  /* XXX: avoid this copy? */;
  tmp = (*state);
  for(var r: u32 = 0; r < 12; r++) {
    /* XXX: pass by reference! */;
    (*state)[r] = mdsRowShfNaive(r, tmp);
  };
}

fn mdsRowShfNaive(r: u32, v: array<BigInt, 12>) -> BigInt {
  var res: BigInt = BigInt(array<u32, 2>());
  var val: BigInt;
  for(var i: u32 = 0; i < 12; i++) {
    mul_lmut_l_l((&val), v[((i + r) % 12u)], mdsCirc[i]);
    add_lmut_l_l((&res), res, val);
  };
  mul_lmut_l_l((&val), v[r], mdsDiag[r]);
  add_lmut_l_l((&res), res, val);
  return res;
}

fn partialRoundsNaive_lmut_lmut(state: ptr<function, array<BigInt, 12>>, round_ctr: ptr<function, u32>) {
  for(var i: u32 = 0; i < 22u; i++) {
    constantLayer_lmut_lmut(state, round_ctr);
    (*state)[0] = sboxMonomial((*state)[0]);
    mdsLayer_lmut(state);
    (*round_ctr) = ((*round_ctr) + 1u);
  };
}

fn getCanonical(b: BigInt) -> BigInt {
  var canon: BigInt;
  fromMont_CIOS_lmut_l_l_l((&canon), b, M, 4294967295);
  return canon;
}

fn fromMont_CIOS_lmut_l_l_l(r: ptr<function, BigInt>, a: BigInt, M: BigInt, m0ninv: u32) {
  /* Convert from Montgomery form to canonical BigInt form */;
  var t: BigInt = a;

  { // unrolledIter_i0
  let m: u32 = (t.limbs[0] * m0ninv);
  var C: u32;
  var lo: u32;
  muladd1_gpu_lmut_lmut_l_l_l((&C), (&lo), m, M.limbs[0], t.limbs[0]);

  { // unrolledIter_j1
  muladd2_gpu_lmut_lmut_l_l_l_l((&C), (&t.limbs[0]), m, M.limbs[1], C, t.limbs[1]);
  } // unrolledIter_j1

  t.limbs[1] = C;
  } // unrolledIter_i0


  { // unrolledIter_i1
  let m: u32 = (t.limbs[0] * m0ninv);
  var C: u32;
  var lo: u32;
  muladd1_gpu_lmut_lmut_l_l_l((&C), (&lo), m, M.limbs[0], t.limbs[0]);

  { // unrolledIter_j1
  muladd2_gpu_lmut_lmut_l_l_l_l((&C), (&t.limbs[0]), m, M.limbs[1], C, t.limbs[1]);
  } // unrolledIter_j1

  t.limbs[1] = C;
  } // unrolledIter_i1

  csub_no_mod_lmut_l_l((&t), M, !less(t, M));
  (*r) = t;
}

fn muladd1_gpu_lmut_lmut_l_l_l(hi: ptr<function, u32>, lo: ptr<function, u32>, a: u32, b: u32, c: u32) {
  /* Extended precision multiplication + addition
(hi, lo) <- a*b + c

Note: 0xFFFFFFFF_FFFFFFFF² -> (hi: 0xFFFFFFFFFFFFFFFE, lo: 0x0000000000000001)
      so adding any c cannot overflow

Note: `_gpu` prefix to not confuse Nim compiler with `precompute/muladd1` */;
  (*lo) = mulloadd_co(a, b, c);
  (*hi) = mulhiadd_ci(a, b, 0u);
}

fn mulhiadd_ci(a: u32, b: u32, c: u32) -> u32 {
  /* Multiply-add high with carry in */;
  let hi_product: u32 = mul_hi(a, b);
  return add_ci(hi_product, c);
}

fn muladd2_gpu_lmut_lmut_l_l_l_l(hi: ptr<function, u32>, lo: ptr<function, u32>, a: u32, b: u32, c1: u32, c2: u32) {
  /* Extended precision multiplication + addition + addition
(hi, lo) <- a*b + c1 + c2

Note: 0xFFFFFFFF_FFFFFFFF² -> (hi: 0xFFFFFFFFFFFFFFFE, lo: 0x0000000000000001)
      so adding 0xFFFFFFFFFFFFFFFF leads to (hi: 0xFFFFFFFFFFFFFFFF, lo: 0x0000000000000000)
      and we have enough space to add again 0xFFFFFFFFFFFFFFFF without overflowing

Note: `_gpu` prefix to not confuse Nim compiler with `precompute/muladd2` */;
  (*lo) = mulloadd_co(a, b, c1);
  (*hi) = mulhiadd_ci(a, b, 0u);
  (*lo) = add_co((*lo), c2);
  (*hi) = add_ci((*hi), 0u);
}

