// Node.js benchmark using WHATWG URL (Ada backend)
const { performance } = require('perf_hooks');

const iterations = 100000;
const urlStr = "https://user:pass@example.com:8443/api/v1/resource/items?filter=active&sort=desc#section-1";

// 1. Bench Parse
const startParse = performance.now();
let checksum = 0;
for (let i = 0; i < iterations; i++) {
    const u = new URL(urlStr);
    checksum += parseInt(u.port, 10);
}
const elapsedParseSec = (performance.now() - startParse) / 1000;
const parseOps = iterations / elapsedParseSec;
const parseNs = (elapsedParseSec / iterations) * 1e9;
console.log(`Node.js URL parse:    ${iterations} ops in ${elapsedParseSec.toFixed(6)} s (${Math.round(parseOps)} ops/sec, ${parseNs.toFixed(1)} ns/op, checksum=${checksum})`);

// 2. Bench Resolve
const baseStr = "http://a/b/c/d;p?q";
const refStr = "../../g?y#s";
const startResolve = performance.now();
let resolveChecksum = 0;
for (let i = 0; i < iterations; i++) {
    const u = new URL(refStr, baseStr);
    resolveChecksum += u.pathname.length;
}
const elapsedResolveSec = (performance.now() - startResolve) / 1000;
const resolveOps = iterations / elapsedResolveSec;
const resolveNs = (elapsedResolveSec / iterations) * 1e9;
console.log(`Node.js URL resolve:  ${iterations} ops in ${elapsedResolveSec.toFixed(6)} s (${Math.round(resolveOps)} ops/sec, ${resolveNs.toFixed(1)} ns/op, checksum=${resolveChecksum})`);
