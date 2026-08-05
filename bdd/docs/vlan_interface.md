# Config-created 802.1Q VLAN sub-interfaces

## Overview

As a network operator
I want `set vlan <name> interface <parent>` + `vlan-id <1-4094>`
So zebra-rs creates and owns the kernel VLAN device, deferring
creation until the parent exists and re-creating it when a deleted
parent returns.

Topology: a single namespace with dummy parent interfaces.
```
```

## Config Files

- z1.yaml: both VLAN entries; dum0 exists at apply time, dum1 does not

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Setup namespace and create a VLAN on an existing parent | |
| Creation defers until the parent appears | |
| The sub-interface takes addresses like any other interface | |
| A deleted parent takes the VLAN with it and its return re-creates the VLAN | |
| Changing the VLAN id re-creates the kernel device | |
| Deleting the config entry deletes the kernel device | |
| Teardown topology | |
