# system hostname configuration

## Overview

As a network operator
I want `set system hostname <name>` to define the device's name so
that `show hostname` (and the interactive vty prompt, which tracks
the same running-config leaf via vtyhelper -H) reflects the
configured identity instead of the OS hostname, and falls back to
the OS hostname when the leaf is deleted.

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Build a single-node topology | |
| Configured hostname wins over the OS hostname | |
| Deleting the hostname falls back to the OS hostname | |
| Teardown topology | |
