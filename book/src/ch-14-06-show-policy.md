# Policy Objects

These commands display the route-policy building blocks — the policies
themselves and the named match-sets they reference (prefix-sets,
community-sets, AS-path-sets, key-chains). They report *configuration*
as the daemon has parsed it, which makes them the quickest way to
confirm a set's contents before referencing it from a policy. Every
command honors `-j` / `--json`.

See the [Policy](ch-05-00-policy.md) chapters for how these objects are
written and applied.

## Route policies

### `show policy`

The configured route policies (route-maps) — their ordered terms with
the `match` conditions and `set` / control-flow actions of each.

JSON: the policy set as a structured document.

## Match-sets

All of the set commands share one shape: with no argument they list
every set of that kind; with `name <name>` they show just that one set
(and report an error if the name is unknown).

### `show prefix-set [name <name>]`

IP prefix-sets, each prefix with its optional length qualifier
(`le` / `eq` / `ge`).

```
r1> show prefix-set
prefix-set: INTERNAL
  192.0.2.0/24
  198.51.100.0/24 le 25
prefix-set: EXTERNAL
  203.0.113.0/24 eq 24
```

JSON: an array of `{ name, prefixes: [ { prefix, le, eq, ge } ] }`
(a single object when filtered by `name`).

### `show community-set [name <name>]`

BGP standard community-sets — each member is an exact community value or
a regular expression.

```
r1> show community-set
community-set: CUST_COMMS len: 3
  65000:100
  65000:200
  ^65001:.*
```

JSON: an array of `{ name, members: [ … ] }`.

### `show ext-community-set [name <name>]`

Extended-community sets — route-target / route-origin members, written
`rt:…` / `soo:…`.

```
r1> show ext-community-set
ext-community-set: CUST_RT len: 2
  rt:65000:100
  rt:65001:.*
```

JSON: an array of `{ name, members: [ … ] }`.

### `show large-community-set [name <name>]`

Large-community sets (RFC 8092) — members in `ASN:value:value` form.

```
r1> show large-community-set
large-community-set: LCOMM1 len: 2
  65000:100:1
  65001:.*:.*
```

JSON: an array of `{ name, members: [ … ] }`.

### `show as-path-set [name <name>]`

AS-path-sets — each member is a regular expression matched against the
BGP AS_PATH.

```
r1> show as-path-set
as-path-set: PATHS1 len: 2
  ^65000.*
  65001$
```

JSON: an array of `{ name, members: [ … ] }`.

### `show key-chains [name <name>]`

Authentication key-chains and their keys — algorithm, key length,
send/receive IDs, and the send/accept lifetime windows. Used by IS-IS
and OSPF authentication. The key material itself is never printed.

```
r1> show key-chains
key-chain: PRIMARY
  description: Production authentication
  key 1:
    algo: hmac-sha-256  key-bytes: 32
    send-id: 1  recv-id: 1
    send-lifetime:   2024-01-01T00:00:00 +86400s
    accept-lifetime: 2024-01-01T00:00:00 +86400s
```

JSON: an array of `{ name, description, keys: [ { id, algo, key_bytes,
send_id, recv_id, send_lifetime, accept_lifetime } ] }`.
