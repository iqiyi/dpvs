The test programs in this directory are built with QUIC library [quic-go](https://github.com/quic-go/quic-go).

The version requirements are shown as below.
* Quic-go: v0.42.0
* Golang: v1.21.8

Quic-go may not well support ECN in such distros as Centos 7 (refer to [issue #4396](https://github.com/quic-go/quic-go/issues/4396) for details), in which case the ECN should be disabled using environment varible `QUIC_GO_DISABLE_ECN`.

```sh
export QUIC_GO_DISABLE_ECN=true
```
