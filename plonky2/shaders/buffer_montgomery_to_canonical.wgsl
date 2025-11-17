requires unrestricted_pointer_parameters;

@group(0) @binding(0) var<storage, read_write> buf: array<BigInt>;
@group(0) @binding(1) var<storage, read> num: i32;

var<private> carry_flag: u32 = 0u;
const M: BigInt = BigInt(array(u32(1), u32(4294967295)));
const MontyOne: BigInt = BigInt(array(u32(4294967295), u32(0)));
const PP1D2: BigInt = BigInt(array(u32(2147483649), u32(2147483647)));
const M0NInv: u32 = 4294967295;
const R2modP: BigInt = BigInt(array(u32(1), u32(4294967294)));
const WORKGROUP_SIZE: i32 = 64;

struct BigInt {
  limbs: array<u32, 2>,
};

@compute @workgroup_size(WORKGROUP_SIZE)
fn bufferToCanonical(@builtin(global_invocation_id) global_id: vec3<u32>, @builtin(num_workgroups) num_workgroups: vec3<u32>) {
  /* Assumes the input is a flat buffer of field elements in *Montgomery representation*.
The kernel transforms every field element into canonical representation. */;
  let grid_width: u32 = (num_workgroups.x * 64u);
  let tid: i32 = ((i32(global_id.y) * i32(grid_width)) + i32(global_id.x));
  if ((num <= tid)) {
    return ;
  };
  toCanonical_smut((&buf[tid]));
}

fn toCanonical_smut(r: ptr<storage, BigInt, read_write>) {
  fromMont_CIOS_smut_l_l_l(r, (*r), M, 4294967295);
}

fn fromMont_CIOS_smut_l_l_l(r: ptr<storage, BigInt, read_write>, a: BigInt, M: BigInt, m0ninv: u32) {
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

fn add_co(a: u32, b: u32) -> u32 {
  let result: u32 = (a + b);
  carry_flag = select(0u, 1u, (result < a));
  return result;
}

fn mulhiadd_ci(a: u32, b: u32, c: u32) -> u32 {
  /* Multiply-add high with carry in */;
  let hi_product: u32 = mul_hi(a, b);
  return add_ci(hi_product, c);
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

fn add_ci(a: u32, b: u32) -> u32 {
  let temp: u32 = (a + b);
  let result: u32 = (temp + carry_flag);
  return result;
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

fn csub_no_mod_lmut_l_l(r: ptr<function, BigInt>, a: BigInt, condition: bool) {
  /* Conditionally subtract `a` from `r` in place *without* modular
reduction.

Note: This is constant-time */;
  var t: BigInt = BigInt(array<u32, 2>());
  sub_no_mod___YjG9b0jr1jXlGGbLNhPCgRQ_lmut_l_l((&t), (*r), a);
  ccopy___gIWNSC2oOW4mX8SJJVXvNg_lmut_l_l(r, t, condition);
}

fn sub_no_mod___YjG9b0jr1jXlGGbLNhPCgRQ_lmut_l_l(r: ptr<function, BigInt>, a: BigInt, b: BigInt) {
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

fn ccopy___gIWNSC2oOW4mX8SJJVXvNg_lmut_l_l(a: ptr<function, BigInt>, b: BigInt, condition: bool) {
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
  for(var i: i32 = 0; i < 2; i++) {
    (*a).limbs[i] = slct(b.limbs[i], (*a).limbs[i], cond);
  };
}

fn slct(a: u32, b: u32, pred: i32) -> u32 {
  return select(b, a, (0 <= pred));
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

fn sub_bi(a: u32, b: u32) -> u32 {
  let temp: u32 = (a - b);
  let result: u32 = (temp - carry_flag);
  return result;
}
