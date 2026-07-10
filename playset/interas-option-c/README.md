# Inter AS Option C


## Topology

<img src="../images/InterASOptionC.svg" alt="My diagram">

## Up all nodes

`./up.sh` will set up all namespaces and routing daemon zebra-rs and inject
initial configration.

``` shell
$ ./up.sh
bring up
teardown: stop zebra-rs
teardown: delete namespace e1
teardown: delete namespace e2
teardown: delete namespace s
...
apply config: r3
applied
apply config: d
applied
```

Then you can examine namespaces by:

``` shell
$ ip netns
d
r3
r2
r1
n3
n2
n1
s
e2
e1
```
