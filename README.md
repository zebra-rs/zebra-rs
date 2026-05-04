# zebra-rs

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

## Debian Package

To build a Debian package, we use [`nfpm`](https://github.com/goreleaser/nfpm),
which is written in Go. Please install Go and `nfpm` first:

``` shell
go install github.com/goreleaser/nfpm/v2/cmd/nfpm@latest
```

Make sure `${GOPATH}/bin` (or `${HOME}/go/bin`) is in your `PATH`. Then from
the `packaging/` directory:

``` shell
cd packaging
make amd64   # or: make arm64
```

This produces a `.deb` package for the selected architecture.

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
-> router		Router configuration
-> system		System configuration

zebra#set router bgp
-> global
-> neighbors
-> peer-groups
-> rib

zebra#set router bgp global as 100
zebra#set router bgp global identifier 10.0.0.100
zebra#set router bgp neighbors neighbor 10.0.0.1 pe?
peer-as     peer-group  peer-type
zebra#set router bgp neighbors neighbor 10.0.0.1 peer-as 200
zebra#show
+router {
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
CM: ["router", "bgp", "global", "as", "100"]
CM: ["router", "bgp", "global", "identifier", "10.0.0.100"]
CM: ["router", "bgp", "neighbors", "neighbor", "10.0.0.1", "peer-as", "200"]
zebra#show
router {
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
