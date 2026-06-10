# API library registration

The lua-lsm core ships only the LSM hook glue and the embedded Lua VM
machinery.  The Lua-callable surface (`kernel`, `fs`, `net`, `errno`,
`capability`, `signal`, ...) is provided by independent producer
modules that publish themselves to the core through a small
registration ABI declared in `include/linux/lua_lsm_api.h`.

Each producer can be built either into vmlinux
(`CONFIG_LUA_LSM_LIB_<NAME>=y`) or as a loadable `.ko`
(`CONFIG_LUA_LSM_LIB_<NAME>=m`).  Both forms share the same descriptor
shape, gates, audit emission, and rollback behaviour; only the
registration entry point differs.

## Producer template

```c
#include <linux/lua_lsm_api.h>
#include <linux/module.h>

static const luaL_Reg <name>_funcs[] = {
        { "f", l_f },
        { NULL, NULL },
};

static int <name>_open_extras(lua_State *L)
{
        /* publish constants, attach metatables, etc. */
        return 0;
}

static struct lua_api_lib <name>_desc = {
        .name        = "<name>",
        .funcs       = <name>_funcs,
        .open_extras = <name>_open_extras,
        .owner       = THIS_MODULE,
        .abi_version = LUA_API_LIB_ABI_VERSION,
};

static int __init lua_<name>_lib_init(void)
{
#ifdef MODULE
        return lua_api_lib_register(&<name>_desc);
#else
        return __lua_api_lib_register(&<name>_desc);
#endif
}
module_init(lua_<name>_lib_init);
MODULE_LICENSE("GPL");
```

Built-in producers call `__lua_api_lib_register()` because
`THIS_MODULE` is `NULL` for vmlinux text and the exported
`lua_api_lib_register()` rejects a `NULL` owner.  See
`security/lua/lua_kernel.c` and friends for canonical examples.

## Descriptor

See `include/linux/lua_lsm_api.h` for the kerneldoc.  Field summary:

| Field         | Required | Notes                                              |
|---------------|----------|----------------------------------------------------|
| `name`        | yes      | `require()` name; non-empty, < `LUA_API_LIB_NAME_MAX` |
| `funcs`       | yes      | NULL-terminated `luaL_Reg`; constants-only libs use the empty sentinel |
| `open_extras` | no       | runs after `funcs`; must honour the atomic-context contract below |
| `openf`       | -        | reserved, must be `NULL`                           |
| `owner`       | =m only  | `THIS_MODULE`; pinned by `try_module_get()`        |
| `abi_version` | yes      | `LUA_API_LIB_ABI_VERSION`                          |
| `_reserved`   | yes      | zero-fill                                          |

## Register flow

`lua_api_lib_register()` runs to completion or rolls back; there is no
intermediate observable state.

1. **Argument validation.**  Programming-bug failures return `-EINVAL`
   without an audit record.
2. **Registry-ready gate.**  `-EAGAIN` until `lua_lsm_init()` finishes.
3. **Lockdown gate.**  `-EPERM` at `LOCKDOWN_MODULE_SIGNATURE` or
   stricter.
4. **Signed-API gate.**  When `CONFIG_LUA_LSM_REQUIRE_SIGNED_API=y`,
   `=m` producers must have `module_sig_ok(owner)`; otherwise
   `-EKEYREJECTED`.
5. **Scratch-VM validation.**  Build and tear down a throw-away
   `lvm_state` to catch malformed descriptors before pinning the owner.
6. **Owner pin.**  `try_module_get(owner)`; `-ENODEV` on failure.
7. **Replay.**  Build replacement IRQ and current-task VMs with `desc`
   installed, then atomically swap them in.  On failure, transactional
   rollback before `module_put(owner)`.
8. **Commit.**  `list_add_tail_rcu()` publishes the descriptor and
   bumps `lua_api_lib_generation`; pooled VMs older than the new
   generation are discarded by `lvm_pool_get()`.

The lock order is `modules_mutex -> cpus_read_lock`.

## `open_extras` execution context

`open_extras` is invoked from four sites: scratch validation, replay
build, fresh task-VM construction (`lualibs_openall_dynamic()`), and
the `CPUHP_AP_ONLINE_DYN` callback.  The cpuhp site runs with bottom
halves disabled, so every implementation must:

- not sleep,
- not take blocking locks,
- not allocate with sleeping GFP flags (use `lua_lsm_gfp()`),
- return `-ENOMEM` on allocation failure; other negatives are mapped
  to `-EPROTO` by the core.

Producers that need to attach methods to per-object metatables call
`lua_api_lib_meta_install(L, name, funcs, gc_funcs)` from
`open_extras`.  The core seeds the empty metatables before any
producer runs, so the install is stack-neutral and idempotent for the
regular and raw metatables.

## Return codes

| Errno           | Cause                                                  |
|-----------------|--------------------------------------------------------|
| `0`             | success                                                |
| `-EINVAL`       | argument-shape violation (no audit record)             |
| `-EAGAIN`       | core not ready                                         |
| `-EPERM`        | lockdown gate                                          |
| `-EKEYREJECTED` | signed-API gate                                        |
| `-EEXIST`       | duplicate `name`                                       |
| `-ENODEV`       | owner module is being removed                          |
| `-ENOMEM`       | allocation failure (rollback log, scratch, or replay)  |
| `-EPROTO`       | `open_extras` returned a non-`-ENOMEM` negative errno  |

Failed registrations roll back fully; if rollback cannot prove every
replacement VM has dropped its closures into the owner's text, the
owner pin is intentionally leaked to prevent module-text use-after-free.

## Audit

Every register call that reaches the registry-ready gate emits one
`AUDIT_LUA_LSM_API` (type `1340`) record:

```
op=lua_api_lib_register result=success name=<n> owner=<m|(builtin)> sig_ok=<1|0|builtin> funcs=<n> res=0
op=lua_api_lib_register result=denied  reason=<r> name=<n> owner=<m|(builtin)> sig_ok=<1|0|builtin> funcs=<n> res=<-errno>
```

`reason` is one of `not-ready`, `lockdown`, `unsigned`, `resource`,
`duplicate`, `scratch`, `pin-failed`, `replay`.  `name` is escaped via
`audit_log_untrustedstring()`.  Argument-shape failures (`-EINVAL`) do
not emit a record because they indicate a caller bug, not a security
event.

## CPU hotplug

The core registers a `CPUHP_AP_ONLINE_DYN` callback that re-installs
every published library into a newly-onlined CPU's IRQ slot under
`local_bh_disable()`.  Producers do not need to special-case hotplug
as long as `open_extras` honours the atomic-context contract.

## See also

- `include/linux/lua_lsm_api.h` - kerneldoc for the ABI
- `security/lua/lua_kernel.c` and friends - canonical producers
- `security/lua/lib_registry.c` - core registration implementation
