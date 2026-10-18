# Policy Show Commands

The `show` commands for route policies and the sets they match against.
Every command honors `-j` / `--json`; see
[Operational Show Commands](ch-06-03-show-commands.md) for how to run a
show command and request JSON. See [Policy](ch-05-00-policy.md) for the
configuration.

The examples come from a router with this configuration:

```yaml
prefix-set:
- name: CUSTOMER-NETS
  prefixes:
  - prefix: 10.10.0.0/16
    le: 24
  - prefix: 2001:db8:100::/48
community-set:
- name: INTERNAL
  members:
  - 65001:100
  - no-export
ext-community-set:
- name: TENANT-A
  members:
  - rt:65001:10
large-community-set:
- name: ASN-65001
  members:
  - '65001:1:1'
as-path-set:
- name: FROM-65003
  members:
  - _65003$
key-chains:
  key-chain:
  - name: OSPF-KEYS
    key:
    - key-id: 1
      crypto-algorithm: hmac-sha-256
      key-string:
        keystring: s3cret
policy:
- name: IMPORT-CUSTOMER
  entry:
  - number: 10
    action: permit
    match:
      prefix-set: CUSTOMER-NETS
    set:
      local-preference:
        set: 200
  - number: 20
    action: deny
```

## `show policy`

The route policies, each entry with its sequence number and action
(`permit`, `deny` or `next`), then a line for each of its `match`
conditions, its `call` and its `set` actions, in the keywords the
configuration uses. A `call`
to a policy that does not exist reads `[unresolved: denies]`.

```
r1> show policy
policy-list: IMPORT-CUSTOMER
 entry: 10 permit
  match: prefix-set CUSTOMER-NETS
  set: local-preference set 200
 entry: 20 deny
```

JSON: a list of `{ name, entries: [ { seq, action, match, set } ] }`,
where `match` and `set` hold one key per configured clause, such as
`"prefix_set": "CUSTOMER-NETS"` or
`"local_preference": { "op": "set", "value": 200 }`.

## Match-sets

Each set command lists every set of its kind, or with `name <name>` that
one set, and reports an error for an unknown name.

### `show prefix-set [name <name>]`

IP prefix-sets, each prefix with its length qualifier (`le`, `eq` or
`ge`), if any:

```
r1> show prefix-set
prefix-set: CUSTOMER-NETS
  10.10.0.0/16 le 24
  2001:db8:100::/48
```

JSON: a list of `{ name, prefixes: [ { prefix, le, eq, ge } ] }`, or one
object with `name`.

### `show community-set [name <name>]`

Standard community-sets, with the member count. A member is a community
value, a well-known name, or a regular expression:

```
r1> show community-set
community-set: INTERNAL len: 2
  65001:100
  no-export
```

JSON: a list of `{ name, members: [ … ] }`.

### `show ext-community-set [name <name>]`

Extended-community sets: route-target and route-origin members, written
`rt:…` and `soo:…`, exact or as a regular expression:

```
r1> show ext-community-set
ext-community-set: TENANT-A len: 1
  rt:65001:10
```

JSON: a list of `{ name, members: [ … ] }`.

### `show large-community-set [name <name>]`

Large-community sets (RFC 8092), members in `ASN:value:value` form:

```
r1> show large-community-set
large-community-set: ASN-65001 len: 1
  65001:1:1
```

JSON: a list of `{ name, members: [ … ] }`.

### `show as-path-set [name <name>]`

AS-path sets, each member a regular expression matched against the
AS_PATH:

```
r1> show as-path-set
as-path-set: FROM-65003 len: 1
  _65003$
```

JSON: a list of `{ name, members: [ … ] }`.

## `show key-chains [name <name>]`

Authentication key-chains and their keys, as used by IS-IS, OSPF and BGP
TCP-AO authentication: the description, if any, and for each key its
algorithm, key length, send and receive IDs, if set, and send and accept
lifetimes. The key itself is never printed.

```
r1> show key-chains
key-chain: OSPF-KEYS
  key 1:
    algo: hmac-sha-256
    key-bytes: 6
    send-lifetime: always
    accept-lifetime: always
```

JSON: a list of `{ name, description, keys: [ { id, algo, key_bytes,
send_id, recv_id, send_lifetime, accept_lifetime } ] }`.
