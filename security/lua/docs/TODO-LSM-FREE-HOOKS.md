# LSM Object Free Hook TODO

## Missing free callbacks for managed object blobs

Status: track as an upstream LSM framework enhancement.

The LSM core now allocates composite security blobs for several object
classes.  The allocation side gives LSMs a chance to initialize their
private state, but some object classes do not provide a matching free
callback before the composite blob is released.

Examples in the current tree:

- `security_key_alloc()` allocates `key->security` and calls the
  `key_alloc` LSM hook, but `security_key_free()` only frees
  `key->security`.
- `security_perf_event_alloc()` allocates `event->security` and calls the
  `perf_event_alloc` LSM hook, but `security_perf_event_free()` only
  frees `event->security`.
- `security_tun_dev_free_security()` and `security_ib_free_security()`
  also release the managed blobs directly without giving LSMs a per-object
  cleanup callback.

This is enough for LSMs whose object blob only contains plain data.  It is
not enough for Lua-LSM object properties.  Lua-LSM stores object properties
in a `kvcache_dict`, and that dictionary can own separately allocated
`kvcache_node` objects.  The dictionary must be released with
`kvcache_dict_free()` while the Lua-LSM object blob is still valid.

For that reason Lua-LSM currently does not reserve storage for these object
classes:

```c
.lbs_key = 0,
.lbs_perf_event = 0,
.lbs_tun_dev = 0,
.lbs_ib = 0,
```

This intentionally disables object property support for key, perf_event,
TUN, and Infiniband objects.  Enabling those blobs without framework free
callbacks would risk leaking `kvcache_node` objects and leaving stale module
accounting behind.

The proper fix should be made in the LSM framework, not only in Lua-LSM.
The framework should add and call matching cleanup hooks before releasing
the composite blob, for example:

- `key_free`
- `perf_event_free`
- `tun_dev_free_security`
- `ib_free_security`

The exact hook names and prototypes should be decided upstream.  The design
also needs to define the cleanup call order, allocation-failure rollback
behavior, sleepability, and RCU/object lifetime constraints.

After the framework provides those callbacks, Lua-LSM can reserve blobs for
these objects, initialize their `kvcache_dict` instances in the alloc hooks,
and release them in the corresponding free hooks.
