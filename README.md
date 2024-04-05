# Zebra

This is a routing protocol implementation project Zebra.

## Install Instruction

To build the project, we need protocol buffer's `protoc` compiler.

On Linux,

``` shell
sudo apt install -y protobuf-compiler
```

On macOS,

``` shell
brew install protobuf
```

will be necessary.

After that,

``` shell
make all
make install
```

will install `zebra`, `vtysh` and `vtysh-helper` under `${HOME}/.zebra/bin` directory.
Please add

``` shell
export PATH="${PATH}:${HOME}/.zebra/bin"
```

to your `.bashrc` or `.zshrc` or any of your shell profile.

## Start

To try zebra, please simply launch program called `zebra`.

``` shell
$ zebra &
```

And `vtysh` is command line shell for it.

``` shell
$ vtysh
```

You can play industry standard CLI with it.

``` shell
$ ~ vtysh
zebra>configure
zebra#show
zebra#set?
-> routing		Routing configuration
-> system		System configuration

zebra#set routing bgp
-> global
-> neighbors
-> peer-groups
-> rib

zebra#set routing bgp global as 100
zebra#set routing bgp global identifier 10.0.0.100
zebra#set routing bgp neighbors neighbor 10.0.0.1 pe?
peer-as     peer-group  peer-type
zebra#set routing bgp neighbors neighbor 10.0.0.1 peer-as 200
zebra#show
+routing {
+    bgp {
+        global {
+            as 100;
+            identifier 10.0.0.100;
+        }
+        neighbors {
+            neighbor 10.0.0.1 {
+                peer-as 200;
+            }
+        }
+    }
+}
zebra#commit
CM: ["routing", "bgp", "global", "as", "100"]
CM: ["routing", "bgp", "global", "identifier", "10.0.0.100"]
CM: ["routing", "bgp", "neighbors", "neighbor", "10.0.0.1", "peer-as", "200"]
zebra#show
routing {
    bgp {
        global {
            as 100;
            identifier 10.0.0.100;
        }
        neighbors {
            neighbor 10.0.0.1 {
                peer-as 200;
            }
        }
    }
}
```
