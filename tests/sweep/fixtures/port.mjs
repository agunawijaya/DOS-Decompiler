// JavaScript candidates for sweep.asm's routines, for `emuverify.py sweep`.
//
// A JavaScript number is a 64-bit float, and its bitwise operators work on
// 32-bit signed integers. A 16-bit machine is neither, so a port has to say
// where it wraps:
//
//   (v << 16) >> 16      the low 16 bits, signed      (what CWD, IMUL keep)
//   v & 0xffff           the low 16 bits, unsigned
//   (v & 0xffff) >>> n   SHR: an unsigned shift of a 16-bit value
//   (v << 16) >> 16 >> n SAR: a signed one
//   Math.imul(a, b)      a 32-bit product, exact where a * b may not be
//   Math.trunc(p / q)    IDIV's quotient: toward zero, not down
//   -32768 < q <= 32767  the quotients an 8088's word IDIV returns; any
//                        other, -32768 included, is the divide fault
//
// The functions whose names describe a mistake are wrong on purpose, each at
// one boundary; tests/sweep/regress.py expects the sweep to stop at exactly
// the first input where it shows. Every divide is an 8088's, the sweep's
// default CPU; the ones that divide as a 386 does say so in their names.

const int16 = (v) => (v << 16) >> 16;

// IDIV on an 8088: null for the divide fault, else the quotient.
const idiv8088 = (dividend, divisor, low, high) => {
  if (divisor === 0) return null;
  const q = Math.trunc(dividend / divisor);
  return low < q && q <= high ? q : null;
};

export function muldiv([a, b, c], ctx) {
  const product = int16(Math.imul(a, b));          // IMUL, of which C keeps AX
  const q = idiv8088(product, c, -32768, 32767);
  return q === null ? { fault: "divide" } : { ax: q };
}

export function muldivWithoutWrap([a, b, c], ctx) {
  const product = a * b;                           // never wraps at 16 bits
  const q = idiv8088(product, c, -32768, 32767);
  return q === null ? { fault: "divide" } : { ax: q };
}

export function muldivWithoutTrunc([a, b, c], ctx) {
  const product = int16(Math.imul(a, b));
  if (idiv8088(product, c, -32768, 32767) === null) {
    return { fault: "divide" };
  }
  return { ax: product / c };                      // a fraction where IDIV truncates
}

export function quot7([n], ctx) {
  const q = idiv8088(n, 7, -32768, 32767);         // DX:AX by CX
  return q === null ? { fault: "divide" } : { ax: q };
}

export function quot7AsA386Divides([n], ctx) {
  const q = Math.trunc(n / 7);                     // -32768 kept, as a 386 keeps it
  return q < -32768 || q > 32767 ? { fault: "divide" } : { ax: q };
}

export function clampStore([x], ctx) {
  const limit = ctx.globals.g_limit;
  if (x > limit) {
    return { writes: { g_over: x - limit, g_hits: ctx.globals.g_hits + 1 } };
  }
  return { writes: { g_under: (x & 0xffff) >>> 2 } };  // SHR
}

export function clampStoreSignedShift([x], ctx) {
  const limit = ctx.globals.g_limit;
  if (x > limit) {
    return { writes: { g_over: x - limit, g_hits: ctx.globals.g_hits + 1 } };
  }
  return { writes: { g_under: x >> 2 } };              // SAR where SHR was meant
}

export function rare([x], ctx) {
  return { ax: x === 0x1234 ? 7 : x & 0xff };
}

// Never return for x = 16 (and, in the second, x = 32): the sweep's case
// timeout kills the Node process, restarts it once, and blocks the second time.
export function rareLoopsAtSixteen([x], ctx) {
  while (x === 16) {}
  return { ax: x === 0x1234 ? 7 : x & 0xff };
}

export function rareLoopsAtSixteenAndThirtyTwo([x], ctx) {
  while (x === 16 || x === 32) {}
  return { ax: x === 0x1234 ? 7 : x & 0xff };
}

export function caller([a, b], ctx) {
  let r = ctx.call("helper", a, b);
  if (a < b) {                                         // signed, as JGE is
    r += ctx.call("helper", b, 1);
  }
  return { ax: r };
}

export function callerUnsignedCompare([a, b], ctx) {
  let r = ctx.call("helper", a, b);
  if ((a & 0xffff) < (b & 0xffff)) {                   // JAE's test where JGE's was
    r += ctx.call("helper", b, 1);
  }
  return { ax: r };
}
