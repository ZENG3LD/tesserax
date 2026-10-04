# tesserax-wireguard

Kernel WireGuard link for tesserax, brought up with `ip` and `wg`. No userspace UDP stack.

`validate` checks a `LinkConfig` without reading the private key file. `plan` is the exact `ip` / `wg` argument list (including `ip link show` for an adjacent QEMU tap). `apply` runs that plan through a `Runner`. The Linux `CommandRunner` passes the key path to `wg` and never opens the file. There is no QEMU spawn and no userspace WireGuard fallback.

Licensed under either of MIT or Apache-2.0, at your option.
