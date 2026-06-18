# Control Flow

Every policy is an ordered list of *entries*. Each entry is keyed
by an integer sequence number and has three parts:

```console
policy NAME {
    entry SEQ {
        action {permit | next | deny};
        match {
            ...;
        }
        set {
            ...;
        }
    }
}
```

The walker visits entries in ascending sequence-number order. For
each entry it evaluates all `match` clauses (they are AND'd
together — see the next section). If every `match` clause
succeeds the entry *fires* and its `action` decides what happens
next. If any `match` clause fails the entry is skipped and the
walker moves on.

`action` is mandatory on every entry — there is no implicit
default.

## The three actions

### `permit` — accept and stop

Apply the entry's `set` clauses, then return the (possibly
modified) route. The walker stops. Subsequent entries are not
evaluated.

```console
policy ACCEPT-CUSTOMER-A {
    entry 10 {
        action permit;
        match {
            prefix-set CUSTOMER-A;
        }
        set {
            local-preference {
                set 200;
            }
        }
    }
}
```

A route inside `CUSTOMER-A` gets `LOCAL_PREF=200` and is accepted.
A route outside falls through to the next entry — but there are
no more entries, so it hits the default-deny rule (see below).

### `next` — apply set, then keep scanning

Apply the entry's `set` clauses to the working attribute set, then
move to the next entry without producing a verdict. Lets you
layer modifications across several entries.

```console
policy LAYERED {
    entry 10 {
        action next;
        match {
            prefix-set CUSTOMER-A;
        }
        set {
            community {
                name TAG-CUST-A;
                additive;
            }
        }
    }
    entry 20 {
        action next;
        match {
            as-path FROM-AS65003;
        }
        set {
            local-preference {
                set 50;
            }
        }
    }
    entry 30 {
        action permit;
    }
}
```

A route in `CUSTOMER-A` whose AS_PATH also matches `FROM-AS65003`
gets *both* the community tag and the lowered `local-preference`,
then is accepted by entry 30 (an unconditional `permit`).

### `deny` — reject, do not apply set

Drop the route. The entry's `set` clauses are *not* applied — a
denied route never picks up incidental modifications.

```console
policy BLOCK-MARTIANS {
    entry 10 {
        action deny;
        match {
            prefix-set MARTIANS;
        }
    }
    entry 20 {
        action permit;
    }
}
```

Routes in `MARTIANS` are dropped at entry 10. Everything else
falls through to entry 20 and is accepted.

## Default-deny

If the walker reaches the end of the policy without producing a
permit verdict, the route is **rejected**. This includes the case
where the only matching entries fall through with `next`:

```console
policy ENDS-ON-NEXT {
    entry 10 {
        action next;
        match {
            prefix-set CUSTOMER-A;
        }
        set {
            community {
                name TAG-CUST-A;
                additive;
            }
        }
    }
}
```

This policy *drops* every route — even routes in `CUSTOMER-A`,
because the only match path falls through to the end of the list
with no permit. To accept the modified route, the policy must
end with a permit:

```console
policy CORRECT {
    entry 10 {
        action next;
        match {
            prefix-set CUSTOMER-A;
        }
        set {
            community {
                name TAG-CUST-A;
                additive;
            }
        }
    }
    entry 20 {
        action permit;
    }
}
```

The default-deny rule is also why a policy with only `match` and
no entries that ever permit is equivalent to "drop everything".

## "Default permit" pattern

To express "modify routes that match, accept everything else", end
the policy with an unconditional `permit`:

```console
policy DEFAULT-PERMIT {
    entry 10 {
        action permit;
        match {
            prefix-set CUSTOMER-A;
        }
        set {
            local-preference {
                set 200;
            }
        }
    }
    entry 20 {
        action deny;
        match {
            prefix-set MARTIANS;
        }
    }
    entry 99 {
        action permit;
    }
}
```

Routes in `CUSTOMER-A` permit at entry 10 with their LP boosted.
Routes in `MARTIANS` deny at entry 20. Anything else falls
through to entry 99 and is accepted unchanged.

## Worked example: precedence and termination

```console
policy ORDER-DEMO {
    entry 10 {
        action deny;
        match {
            prefix-set BLOCKLIST;
        }
    }
    entry 20 {
        action permit;
        match {
            prefix-set VIPS;
        }
        set {
            local-preference {
                set 300;
            }
        }
    }
    entry 30 {
        action next;
        match {
            community {
                name HAS-NO-EXPORT;
            }
        }
        set {
            community {
                name TAG-INTERNAL;
                additive;
            }
        }
    }
    entry 40 {
        action permit;
    }
}
```

For a route 1.2.3.4/32 with community `65001:42`:

| Entry | Match? | Effect |
|-------|--------|--------|
| 10 | not in `BLOCKLIST` | skipped |
| 20 | not in `VIPS` | skipped |
| 30 | community `no-export` not present | skipped |
| 40 | unconditional | `permit` — accept the route unchanged |

For a route in `BLOCKLIST`:

| Entry | Match? | Effect |
|-------|--------|--------|
| 10 | yes | `deny` — drop, walker stops, no `set` applied |

For a route in `VIPS`:

| Entry | Match? | Effect |
|-------|--------|--------|
| 10 | not in `BLOCKLIST` | skipped |
| 20 | yes | apply `LP=300`, `permit` — accept and stop |
