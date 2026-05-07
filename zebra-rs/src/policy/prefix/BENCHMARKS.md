# prefix-set match performance

Benchmark of `PrefixSet::matches()` after switching from a linear scan
over a `BTreeMap<IpNet, _>` to a per-family binary radix trie
(`PrefixTrie`) keyed on MSB-aligned bits.

## Results

10,000 IPv4 `/32` queries against a set of `n` IPv4 `/24` prefixes,
release build. Both columns produce the same hit count (40), confirming
algorithmic equivalence.

| Set size  | Linear scan | Trie        | Speedup     |
| --------- | ----------- | ----------- | ----------- |
| 100       | 2.26 ms     | 59 µs       | 38×         |
| 1,000     | 23.3 ms     | 30 µs       | 771×        |
| 10,000    | 234 ms      | 32 µs       | 7,282×      |
| 100,000   | 2.60 s      | 34 µs       | 75,492×     |

The trie time is essentially flat across set sizes because lookup depth
is bounded by the prefix length (≤32 for IPv4, ≤128 for IPv6) regardless
of `n`. The linear scan grows linearly with `n`, exactly as the original
O(n) algorithm predicts.

## Complexity

| Operation        | Old (linear)        | New (trie)                 |
| ---------------- | ------------------- | -------------------------- |
| `matches()`      | O(n)                | O(L + k · log n)           |
| `insert/remove`  | O(log n)            | O(L + log n)               |

Where:
- `n` = number of prefixes in the set
- `L` = prefix length of the query (≤32 for v4, ≤128 for v6)
- `k` = number of enclosing prefixes encountered along the trie walk
  (typically ≤ `L`, in practice much smaller)

The `log n` term in the new `matches()` comes from the `BTreeMap::get`
done for each enclosing prefix to fetch its `le/eq/ge` entry; the trie
itself only stores key markers.

## Reproducing

The benchmark lives as an `#[ignore]`d test inside
`zebra-rs/src/policy/prefix/set.rs` (`bench_matches_vs_linear_scan`).
Run it with:

```
cargo test --release --bin zebra-rs -- \
    --ignored --nocapture bench_matches_vs_linear_scan
```

The test asserts that the trie and the in-place reference linear scan
return identical hit counts for every workload, so any regression in
correctness will fail the test rather than silently affect the timings.

## Environment

- CPU: aarch64, 4 cores
- Kernel: Linux 6.8.0
- Toolchain: rustc 1.95.0 (release profile)
- Date: 2026-05-07
