# Lua-LSM API Reference

Lua-LSM lets you write kernel security policy as Lua modules and load them at
runtime through securityfs. This document is the reference for writing those
modules: the module format, the execution model, the hook contract, and every
API a policy can call.

For building and enabling Lua-LSM, and for the securityfs commands that load
and unload modules, see `USAGE.md`. For stats and debug output, see
`OBSERVABILITY.md`.

Everything here is derived from the implementation in `security/lua/`. Where a
detail is easy to get wrong, the source location is cited so you can check it.

## Contents

- [Module format](#module-format)
- [Execution model](#execution-model)
- [Hook contract](#hook-contract)
- [The Lua environment](#the-lua-environment)
- [Per-object storage and shared dicts](#per-object-storage-and-shared-dicts)
- [Object reference](OBJECTS.md) — separate file
- [Library reference](LIBRARIES.md) — separate file
- [Hook reference](#hook-reference) (full table in [HOOKS.md](HOOKS.md))
- [Patterns](#patterns)
- [Pitfalls](#pitfalls)

## Module format

A module is a Lua chunk that **returns a table**. The table carries metadata
fields and one function per LSM hook you want to intercept.

```lua
local errno = require("errno")

local M = {
  name        = "demo",          -- required, string, must be unique
  author      = "example",       -- optional, string
  description = "Deny reads of /etc/shadow",  -- optional, string
  license     = "GPL-2.0",       -- optional, string
  version     = 1,               -- optional, number
}

function M.file_open(file)
  local path = file:path()
  if path == "/etc/shadow" then
    return false, errno.EPERM
  end
  return true
end

return M
```

### Metadata fields

| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| `name` | string | **yes** | Registration fails without it. Must not collide with an already registered module (`-EEXIST`). Also the key used to unregister. |
| `author` | string | no | Shown in `/sys/kernel/security/lua/modules`. |
| `description` | string | no | Free text. |
| `license` | string | no | Free text; not enforced. |
| `version` | number | no | Truncated to `int`. |

A metadata field of the wrong type is logged and **skipped**, not fatal
(`security/lua/lsm.c:1040`). Registration only hard-fails when the chunk does
not return a table (`-EBADF`), when `name` is missing, when a hook name is not
supported (`-EOPNOTSUPP`), or when the name is already taken (`-EEXIST`). A
missing `name` reports `-ENOMEM` (`security/lua/lsm.c:1091`), which looks like
an allocation failure but is not, so read that errno from a failed load as
"check the metadata table first".

### Hook fields

Any other key in the table is matched against the LSM hook names. A key that
matches a hook name must hold a function; if it does not, the entry is logged
and ignored (`security/lua/lsm.c:1071`). A key that matches nothing is logged
as `field '<key>' is unknown` and ignored — **a typo in a hook name silently
disables that hook**, so check the kernel log after loading a policy.

Enumerate the supported hook names from Lua or from userspace:

```lua
local kernel = require("kernel")
local hooks = kernel.lsm_funcs()
```

```sh
cat /sys/kernel/security/lua/lsm_funcs   # requires CONFIG_SECURITY_LUA_LSM_STATS
```

Some LSM hooks are deliberately **not** exposed; naming one makes registration
fail with `-EOPNOTSUPP` (`security/lua/lsm.h:54`):

`getprocattr`, `setprocattr`, `lsmprop_to_secctx`,
`xfrm_state_pol_flow_match`, `watch_key`,
`key_alloc`, `key_permission`, `key_getsecurity`,
`perf_event_open`, `perf_event_alloc`, `perf_event_read`, `perf_event_write`,
`tun_dev_alloc_security`, `tun_dev_create`, `tun_dev_attach_queue`,
`tun_dev_attach`, `tun_dev_open`,
`ib_pkey_access`, `ib_endport_manage_subnet`, `ib_alloc_security`.

## Execution model

Understanding this section prevents most policy bugs.

### The chunk runs more than once

Your chunk is executed:

1. **Once at registration time**, in a throwaway VM, to obtain the metadata
   table (`security/lua/lsm.c:986`). It then gets compiled to bytecode and
   stored.
2. **Once per Lua VM that needs it**, lazily, when a task first triggers one of
   your hooks (`security/lua/lsm.c:750`).

Two consequences:

- **Top-level code must not index `current` or `shared`.** `module_load()`
  installs both in the per-module environment *before* it loads and pcalls the
  chunk (`security/lua/lsm.c:685`, `:688`, `:717`), so in a per-VM load they
  are already present at the top level. The registration run is the exception:
  it pcalls the chunk against the plain global environment
  (`security/lua/lsm.c:986`), where both read as `nil`. Reading a `nil` is not
  an error, but indexing one raises, and that error fails the load. Use them
  only inside hook functions.
- **Top-level state is per-VM, not global.** A counter declared as a local
  upvalue at the top of your chunk is private to one VM, so it counts only the
  activity that VM handled. For state shared across the whole system, use
  `shared` (see below).

### One VM per task

A Lua VM is bound to the task that triggers a hook, taken from a per-CPU pool
(`security/lua/lsm.c:324`, `lvm_get()` at `security/lua/lsm.c:560`). Hooks run
**synchronously, in the context of the syscall being checked**, on the caller's
kernel stack. Some hooks run in softirq/NAPI context. Therefore:

- Keep hooks short. Every microsecond is added to a syscall on the hot path.
- Never build unbounded data structures in a hook; VM memory comes from
  `krealloc()` with a non-sleeping GFP (`security/lua/lsm.c:831`).
- Pool size is tunable at boot with `lua.lvm_pool_max=` (see `USAGE.md`).

If no VM can be obtained, the plain int, `INT_BOOLERR` and `INT_NAKED` families
fail **closed** with `-ENOMEM`; the void and `INT_BOOL` families fall back to
the hook's default, because they are declared with `failret = DEFAULT`
(`security/lua/lsm_defs.h:325`, `:394`). Task teardown is a separate case: when
`lvm_current_task_teardown()` reports that the current task is going away, every
family short-circuits to the default and none of them fails closed
(`security/lua/lsm_defs.h:265`, `security/lua/lsm.c:445`).

### Multiple modules, first non-default wins

For each hook, live modules are visited in **registration order**. After each
module's function returns, the dispatcher compares the result against the
hook's default: if it differs, the chain **stops there**
(`RET_CHECK_int`, `security/lua/lsm_defs.h:182`).

- The first module to deny wins; later modules do not run for that call.
- Returning `true` on a hook whose default is `0` (allow) does **not** stop the
  chain, because the value equals the default.
- Void (notification) hooks never short-circuit; every module sees them.

### Errors fall back to the default

If your hook function raises, the dispatcher logs the error, pops it, and
leaves the return value at the hook's default (`security/lua/lsm_defs.h:166`).
For most hooks the default is `0`, meaning **an error in your policy allows the
operation**. If a check must fail closed, wrap the fallible part in `pcall()`
and decide explicitly:

```lua
local errno = require("errno")

function M.file_open(file)
  local ok, verdict = pcall(inspect, file)
  if not ok then
    return false, errno.EACCES   -- fail closed on a policy bug
  end
  return verdict
end
```

## Hook contract

A hook function receives the objects the kernel passed to that LSM hook (see
[Hook reference](#hook-reference)) and returns a verdict. There are four
decoders, and which one applies depends on the hook.

### Int-returning hooks (the common case)

| You return | Kernel sees |
| --- | --- |
| nothing, or `nil` | the hook's default (usually `0` = allow) |
| `true` | `0` — allow |
| `false` | `-EPERM` |
| `false, errno` | `-errno` |
| `nil, errno` | `-errno` |

`errno` must be a positive number `<= MAX_ERRNO`; anything else leaves the
default in place (`security/lua/lsm_defs.h:77`). Use `require("errno")` for the
constants rather than hardcoding numbers.

A single **non-boolean** return value is ignored and the default applies
(`security/lua/lsm_defs.h:99`). In particular `return 0` and `return
errno.EPERM` do **not** work — `return true` and `return false, errno.EPERM`
do.

### Predicate hooks

A few hooks report a boolean to the kernel rather than an errno. Return a
boolean; `true` becomes `1` and `false` becomes `0`
(`security/lua/lsm_defs.h:114`). A non-boolean is ignored.

### Predicate-or-errno hooks

These accept both spellings (`security/lua/lsm_defs.h:123`): `true` → `1`,
`false, errno` → `-errno`, `nil, errno` → `-errno`.

### Void (notification) hooks

The return value is discarded entirely — the kernel requests zero results
(`LCALL_NRES_void`, `security/lua/lsm_defs.h:155`). Use these to observe and
record, never to decide. All modules run; there is no short-circuit.

The [Hook reference](#hook-reference) names the decoder and default for every
hook.

## The Lua environment

Lua-LSM embeds Lua 5.1 in the kernel. The standard libraries are opened
(`luaL_openlibs`, `security/lua/lsm.c:854`), so `string`, `table`, `math`,
`pcall`, `type`, `tostring` and friends behave as usual.

Differences from stock Lua that matter:

- **`_G` is removed.** `_G._G` is set to `nil` (`security/lua/lsm.c:866`), so
  you cannot reach the global table by name.
- **`require` is replaced, and it is mandatory.** It only looks up the built-in
  libraries already registered in `_LOADED` (`ll_require`,
  `security/lua/lsm.c:822`); there is no filesystem or package path. The
  libraries are *not* installed as globals — `luaL_requiref()` is called with
  `glb = 0` (`security/lua/lsm.c:817`, `security/lua/auxlib.c:208`) — so you
  must write `local fs = require("fs")` before using `fs`. An unknown name
  returns `nil` instead of raising, so a typo in a library name surfaces later
  as "attempt to index a nil value".
- **No `bit` library, no `io`, no `os` facilities you would expect in
  userspace.** Decode multi-byte values arithmetically or with `string.byte`.
- **Assigning a global is allowed but logged.** The module environment's
  `__newindex` warns `set global variable` and then performs the assignment
  (`security/lua/lsm.c:661`). Prefer `local`.
- **Numbers are 64-bit integers.** `LUA_NUMBER` is `long long` in kernel
  builds (`include/linux/luaconf.h:502`), so there is no float rounding, and
  division truncates.

Two names are injected into every module's environment:

| Name | What it is |
| --- | --- |
| `current` | A `task` object for the task currently executing the hook. Refreshed before every hook call (`security/lua/lsm_defs.h:287`). Its methods (`current:pids()`, `current:comm()`, ...) work everywhere, but it **cannot carry kvcache labels** — see [Labelling kernel objects](#labelling-kernel-objects). |
| `shared` | A table that hands out named shared dicts, scoped to your module (`security/lua/lsm.c:695`). |

Both are in place before a per-VM load starts executing your chunk, so they are
visible at the top level there; they are `nil` only during the registration run.
Confine your use of them to hook bodies, which is the one place both spellings
are always populated.

## Per-object storage and shared dicts

Lua-LSM gives a policy two places to keep state. Both are key/value stores
implemented in `security/lua/kvcache.c`.

### Labelling kernel objects

A kernel object that a hook passes **as an argument** (`task`, `cred`, `file`,
`inode`, `sock`, `superblock`, ipc objects, `key`, ...) accepts arbitrary keys.
Reading a key that is not a method falls through to a per-object store, and
writing a key stores it there (`lua_object_index`/`lua_object_newindex`,
`security/lua/kvcache.c:635`, `:659`). The store is **scoped to your module** —
two modules can use the same key name on the same object without colliding — and
the data lives as long as the kernel object does.

```lua
function M.inode_permission(inode, mask)
  if inode:ino() == 2 then
    inode.is_root_inode = true      -- label the inode
  end
end
```

**`current` is the exception: it cannot carry labels.** The injected `current`
object is built without the module binding (`newtask_nomain`,
`security/lua/lsm.c:685`), so a write through `current` is silently dropped
(`kvcache` returns `-ESRCH`) and a read returns nothing. Its *methods* still
work — `current:pids()`, `current:comm()`, `current:cred()` are fine — only
label storage on `current` fails. Do not write `current.trusted = true`; it
looks like it works and does nothing.

To carry state that belongs to the acting task across hooks, key a shared dict
by its tgid. `current:pids()` gives you that tgid in any hook, even ones like
`file_open` that receive no task argument:

```lua
local ROLE = { service = 2 }

function M.bprm_committed_creds(bprm)
  local exe = bprm:executable()
  if exe and exe:path() == "/usr/bin/nginx" then
    local _, tgid = current:pids()
    shared.roles:set(tgid, ROLE.service)   -- classify at exec
  end
end

function M.file_open(file)
  local _, tgid = current:pids()
  if shared.roles:get(tgid) == ROLE.service then
    return true                            -- enforce at open
  end
end
```

Delete the entry when the task exits (a `task_free` hook, or set it to `nil`)
so the dict does not fill — see [Limits and lifetime](#limits-and-lifetime).

### Shared dicts

`shared.<name>` returns a dict shared by every task and CPU, scoped to your
module (`security/lua/lsm.c:580`). It is created on first access. Writing to
`shared` itself is rejected and logged (`security/lua/lsm.c:653`) — write into
a dict, not into `shared`.

```lua
function M.socket_connect(sock, address)
  local counters = shared.counters
  counters:incr("connects", 1)
end
```

Methods: `set(key, value)`, `get(key)`, `incr(key, delta)`, plus index sugar
(`d.k = v`, `d.k`) and `tostring(d)` for a usage summary
(`security/lua/kvcache.c:731`).

### Value and key types

A dict entry is a fixed-size scalar slot, not a Lua value. The key is a
string, and the value is one of three scalar types. Everything else is
either rejected or raises.

| Lua type | As a key | As a value |
|---|---|---|
| string | legal, used verbatim | **rejected**, `nil, "-EINVAL"` |
| number | legal, coerced to its string form | legal, stored as an integer |
| boolean | raises | legal |
| light userdata | raises | legal, raw pointer is stored |
| `nil` | raises | deletes the entry, returns `true` |
| table, function, thread, full userdata | raises | **rejected**, `nil, "-EINVAL"` |

Keys go through `luaL_checklstring()`, so a number key is coerced by Lua
itself: `d[1]`, `d["1"]` and `d:get(1)` are all the same entry. Any other
key type raises a Lua error (`bad argument #2 ... string expected, got
table`), which aborts the hook and makes it return its default verdict;
you do not get a `nil, err` pair for a bad key.

Values are gated by a single `switch` on the Lua type
(`security/lua/kvcache.c:272`), which accepts only boolean, number and
light userdata. A number is stored as `lua_Number`, which is `long long`
in kernel builds, so fractions are truncated.

Because strings are rejected, a policy cannot store a label as text. Use
one of three encodings instead. Intern the label set as numeric codes and
store the code; store one boolean per label when the labels are
independent flags; or store a number that indexes a Lua-side table held in
the module chunk, which also gives you the reverse mapping for audit
messages. All three cost one entry per object.

```lua
local errno = require("errno")
local CODE  = { unconfined = 0, sandbox = 1, admin = 2 }

function M.file_open(file)
    local ok, err = file:kvcache_set("label", CODE.sandbox)
    if not ok then
        return false, errno.EPERM
    end
    return true
end
```

### Reading and writing

Every dict is reachable in two forms. The explicit method form returns the
full result, and the sugar form goes through `__index` / `__newindex` and
returns only a value.

| Operation | Shared dict | Kernel object | Returns |
|---|---|---|---|
| write | `d:set(k, v)` | `obj:kvcache_set(k, v)` | `true`, or `nil, "-EXXX"` |
| read | `d:get(k)` | `obj:kvcache_get(k)` | the value, or `nil` |
| add | `d:incr(k, delta)` | `obj:kvcache_incr(k, delta)` | the new number, or `nil, "-EXXX"` |
| sugar write | `d.k = v` / `d[k] = v` | `file.trusted = true` | nothing |
| sugar read | `d.k` / `d[k]` | `file.trusted` | the value, or `nil` |

Test writes with `not ok`: a failing `set` returns `nil` as its first
result, never `false`. Test reads with `== nil`, and treat `nil` as
"unknown" rather than "absent". A missing key pushes a real `nil`
(`security/lua/kvcache.c:423`), but an object with no dict, or one whose
owning module could not be resolved, returns **no value at all**
(`security/lua/kvcache.c:591`). Under an assignment (`local v =
obj:kvcache_get(k)`) both read as `nil`, so always bind the result to a
variable — feeding the call straight into another function, as in
`tostring(obj:kvcache_get(k))`, raises when there is no value.

The sugar form discards the error pair, because the Lua VM ignores what
`__newindex` returns. A `-EINVAL`, `-ERANGE` or `-ENOMEM` from
`file.k = v` or `d[k] = v` is therefore **silent**: the assignment
looks like it worked and the next read gives `nil`. Use the method form
wherever a lost write changes the verdict.

```lua
local errno = require("errno")

function M.file_open(file)
    local ok, err = shared.opens:set("last_seen", 1)
    if not ok then
        -- err is "-ERANGE" once the dict is full
        return false, errno.EPERM
    end
    return true
end
```

Reads consult the metatable chain before the dict, so method names shadow
data keys: `file.path`, `d.get`, `d.set`, `d.incr`, `obj.type` and
`obj.kvcache_get` all return the function, not your entry
(`security/lua/kvcache.c:635`, `:696`). A write is not shadowed —
`file.path = 1` really does store an entry named `"path"`, which you can
then only read back with `file:kvcache_get("path")`. Do not name a label
after a method.

### incr

`incr` is the only atomic read-modify-write in the store.

- `delta` is optional and defaults to `1`. A non-number `delta` raises.
- A missing key is **created** with the value `delta` and returns `delta`;
  there is no "must exist" mode and nothing to bootstrap.
- An existing number is incremented under the entry's write lock and the
  new total is returned.
- An existing boolean or light userdata is left untouched and the call
  returns `nil, "-EINVAL"`.
- Creating the key can fail like any other insert: `nil, "-ERANGE"` when
  the dict is full, `nil, "-ENOMEM"` on allocation failure.
- There is no `decr`; pass a negative delta.
- There is no sugar form. `d[k] = d[k] + 1` is two separate locked
  operations and loses updates under concurrency.

```lua
function M.file_open(file)
    local n = shared.opens:incr("total")      -- creates at 1, then 2, 3, ...
    if n and n > 10000 then
        shared.opens:set("total", nil)        -- free the entry again
    end
    return true
end
```

### Limits and lifetime

Every dict holds at most `CACHE_CAPACITY` = **1024** entries. The capacity
is written once at dict init and nothing in the tree ever raises it
(`security/lua/kvcache.h:20`, `security/lua/kvcache.c:70`). Inserting a
new key into a full dict fails with `nil, "-ERANGE"`; overwriting an
existing key always succeeds, since it does not need a slot.

There is no eviction. No LRU, no TTL, no expiry field, no reclaim on
memory pressure. An entry disappears only when you set it to `nil`, when
your module is unregistered, or when the owning kernel object is freed.

The consequence is blunt: a dict keyed on an unbounded key space — a pid,
an inode number, a port, a syscall timestamp — fills to 1024 entries and
then stays full forever, and from that point every new key in that dict
fails with `-ERANGE` while the stale entries keep answering reads. Key on
a bounded space instead: put per-object state on the object itself, where
each object gets its own dict and the kernel frees it for you, and keep
`shared` dicts for a fixed set of named counters and flags. If you must
key `shared` on something unbounded, delete the entry on the matching
teardown hook and treat `-ERANGE` as a bug in your key design rather than
a condition to retry.

```lua
function M.file_open(file)
    file.opened = true                   -- bounded: one dict per file
    local n = shared.stats:incr("opens") -- bounded: one fixed key
    return n ~= nil
end
```

Scope and lifetime differ between the two flavours:

- `shared.<name>` dicts belong to the module, not to a task or a Lua VM.
  They are visible from every task and every CPU, including the per-CPU
  VMs used when a hook runs outside task context, which makes them the
  only cross-task channel a policy has. They are invisible to other
  modules, even a same-named dict. They live for as long as the module is
  registered and are freed at unregister, so unload/reload starts from
  empty; there is no persistence.
- Per-object dicts live exactly as long as the kernel object that owns
  them — a `file` entry dies at file teardown, an `inode` entry at inode
  reclaim, a `task` entry with the task. They are private to your module:
  entries are keyed by `(key, module)`, so another module's `label` on the
  same object is a different entry (`security/lua/kvcache.c:54`).
  Capacity, however, is per dict and shared by all modules, so another
  module can consume the 1024 slots on an object you also use.
- Nothing is inherited. `cred` objects are copy-on-write, so `execve` or
  `setuid` produces a fresh `cred` with an empty dict, and a forked
  child's `task` blob is also empty. Re-derive state in the relevant hook
  instead of assuming it propagates.
- `func`-class object types have no dict at all: `key`, `dentry`, `path`,
  `binprm`, `socket`, `skb`, `sockaddr`, `vfsmount`, `mntidmap`, `cap`,
  `fscontext`, `userns`, `perfevent`, `ib` and `tundev`. They have no free
  hook to hang a teardown on, so properties on them are deliberately
  unsupported: `key.foo = 1` raises an "attempt to index" error and
  `key.foo` reads `nil`. Store such state on a nearby object that does
  have a dict — the `inode` or `file` rather than the `dentry` or `path`.

### Concurrency

Each dict has one `rwlock_t` guarding its tree and each entry has its own
`rwlock_t` guarding its value, and every acquisition uses the
`_irqsave` variants. Lazy dict init spins with `cpu_relax()` rather than
sleeping. Nothing in the path can sleep, and allocation automatically
degrades to `GFP_ATOMIC` when the hook runs in atomic or RCU context, so
`set`, `get` and `incr` are safe from every context a hook can be entered
from, including softirq.

A single `get` copies the whole value under the entry read lock, so you
never see a half-updated value. Two reads are a different matter: another
CPU, or a softirq on the same CPU, can `set`, `incr` or delete between
them, so the second read can disagree with the first even inside one hook
invocation. There is no snapshot, no transaction and no compare-and-swap.
A read-modify-write must therefore use `incr`, which does the whole
update under the entry write lock; `get` followed by `set` loses
concurrent updates.

```lua
local errno = require("errno")

function M.file_open(file)
    local n = shared.quota:incr("open_budget", -1)   -- atomic
    if n and n < 0 then
        shared.quota:incr("open_budget", 1)          -- give it back
        return false, errno.EBUSY
    end
    return true
end
```

### Error strings

The second result of a failed call is an errno *name*, and it carries a
leading minus: `"-EINVAL"`, `"-ERANGE"`, `"-ENOMEM"`, `"-ESRCH"`. The
store formats it with `errname()` on the negative errno it already holds,
and `errname()` keeps the sign (`lib/errname.c:217`). Compare against
`"-ERANGE"`, not `"ERANGE"`. An unrecognised code yields `"unknown"`.
These strings are for logging and for distinguishing "dict full" from
"bad value type"; they are unrelated to the positive `errno.EXXX`
constants a hook returns to deny an operation.

### Inspecting storage from userspace

`/sys/kernel/security/lua/modules` reports two per-module columns:
`shdict` is the number of `shared` dicts the module has created, and
`kvnode` is the number of entries it currently owns in per-object dicts
(entries in `shared` dicts are not counted there). Watching `kvnode` grow
is the supported way to catch a policy walking toward the 1024-entry
limit. See `OBSERVABILITY.md` for the full column list and for the
`stats` counters. Loading and unloading modules through the other
securityfs files is covered in `USAGE.md`.


## Object reference

Every object type a hook hands your policy — `task`, `cred`, `file`, `inode`,
`sock`, `skb`, and the rest — is documented in **`OBJECTS.md`**, including each
method's arguments, return values, and failure mode.

## Library reference

The seven built-in libraries (`kernel`, `fs`, `net`, `errno`, `capability`,
`signal`, `audit`) are documented in **`LIBRARIES.md`**.

## Hook reference

### Reading a hook signature

Each row in `HOOKS.md` gives a hook's name, its ordered Lua arguments, its
return convention, its default return value, and notes. Declare a hook by
adding a key of exactly that name to your module table; the function receives
those arguments in that order.

A plain int hook decides allow or deny:

```lua
local errno = require("errno")

function M.inode_permission(inode, mask)
  if inode:ino() == 2 and mask ~= 0 then
    return false, errno.EACCES
  end
  return true
end
```

A void hook is a notification: the return value is discarded, every loaded
module runs, and there is no short-circuit.

```lua
function M.task_to_inode(p, inode)
  local pid = p:pids()
  shared.stats:set("last_procfs_pid", pid)
end
```

A hook's Lua arity is not always its C arity. `capget` is declared with four C
arguments and passes one:

```lua
local errno = require("errno")

function M.capget(target)
  if target:pids() == 1 then return false, errno.EPERM end
  return true
end
```

### Return conventions

| Convention | Hooks | Lua result to kernel return |
|---|---|---|
| plain int | 210 | `true` -> 0; `false` -> `-EPERM`; `false, errno` / `nil, errno` -> `-errno`; nothing / `nil` / other single value -> default |
| `INT_BOOL` | 4 | `true` -> 1; `false` -> 0; anything else -> default |
| `INT_BOOLERR` | 2 | `true` -> 1; `false` -> 0; `false, errno` / `nil, errno` -> `-errno` |
| `INT_NAKED` | 4 | plain int rules, plus a per-hook success payload form |
| void | 53 | discarded |

The four `INT_BOOL` hooks are `inode_xattr_skipcap`, `ismaclabel`,
`audit_rule_known`, and `xfrm_state_pol_flow_match`; the two `INT_BOOLERR`
hooks are `inode_need_killpriv` and `audit_rule_match`. On all six a boolean is
a predicate answer, not a verdict: `false` means the integer 0, not `-EPERM`.
Writing `return false` there to deny an operation instead answers "no" to the
kernel's question. `xfrm_state_pol_flow_match` also defaults to 1, not 0.

The four `INT_NAKED` hooks are `capget`, `inode_init_security`,
`inode_getsecurity`, and `inode_listsecurity`. Each accepts an extra result
form that fills the C output parameters: three `cap` objects for `capget`, two
strings `(name, value)` for `inode_init_security`, and one string for
`inode_getsecurity` and `inode_listsecurity`.

### Lua arity is not C arity

Seven hooks fold a `ptr, len` pair into one binary Lua string:
`inode_setxattr` (6 C args, 5 Lua), `inode_post_setxattr` (5 to 4),
`inode_setsecurity` (5 to 4), `kernel_post_load_data` (4 to 3),
`kernel_post_read_file` (4 to 3), `setprocattr` (3 to 2), and
`key_post_create_or_update` (6 to 5). `bdev_setintegrity` does not fold — it
passes both the value and the size.

The four `NAKED` hooks drop their output parameters instead: `capget` (4 to 1),
`inode_listsecurity` (3 to 1), `inode_init_security` (5 to 3), and
`inode_getsecurity` (5 to 3).

### Warning: 86 hooks receive a `nil` argument

86 hooks push at least one argument as `nil` with a `TODO` in the
implementation. Those arguments carry no data; do not write policy against
them. `HOOKS.md` marks each one `nil (TODO)`.

23 registered hooks receive no usable argument at all: `settime`,
`vm_enough_memory`, `sb_free_mnt_opts`, `inode_free_security_rcu`,
`kernfs_init_security`, `current_getlsmprop_subj`, `release_secctx`,
`req_classify_flow`, `xfrm_policy_clone_security`, `xfrm_policy_free_security`,
`xfrm_policy_delete_security`, `xfrm_state_alloc`, `xfrm_state_free_security`,
`xfrm_state_delete_security`, `audit_rule_known`, `audit_rule_free`,
`bpf_prog`, `bpf_map_free`, `bpf_prog_free`, `bpf_token_free`,
`bpf_token_cmd`, `locked_down`, and `uring_cmd`. The unregistered
`lsmprop_to_secctx` and `xfrm_state_pol_flow_match` are in the same state. On
these hooks you can decide only from `current` and `shared`.

### Conditional arguments

`socket_bind`, `socket_connect`, and `sctp_bind_connect` drop the `sockaddr`
when the caller's `addrlen` is shorter than the address family requires, so
that argument can be absent. `task_prctl` passes 2 arguments for
`PR_SET_PTRACER` (the string `"set_ptracer"` and the target pid) and 5 for
every other option. Check before use:

```lua
local errno = require("errno")

function M.socket_connect(sock, address)
  if not address then return true end
  local kind, addr, port = address:addrs()
  if kind == "inet" and port == 25 then
    return false, errno.EACCES
  end
  return true
end
```

### Restricted objects

`file_alloc_security` and `file_free_security` receive a `raw` file object that
supports only `kvcache_set`, `kvcache_get`, `kvcache_incr`, and `type`. Normal
`file` methods such as `file:path()` are unavailable; calling one raises a Lua
error, which leaves the hook default in place.

### Hooks you cannot declare

20 hooks exist in the C source but are never registered with the kernel:
`getprocattr`, `setprocattr`, `lsmprop_to_secctx`,
`xfrm_state_pol_flow_match`, `watch_key`, `key_alloc`, `key_permission`,
`key_getsecurity`, `perf_event_open`, `perf_event_alloc`, `perf_event_read`,
`perf_event_write`, `tun_dev_alloc_security`, `tun_dev_create`,
`tun_dev_attach_queue`, `tun_dev_attach`, `tun_dev_open`, `ib_pkey_access`,
`ib_endport_manage_subnet`, and `ib_alloc_security`. Naming one makes the whole
module fail to load with `-EOPNOTSUPP`. `HOOKS.md` marks them
`Not registered`.

`HOOKS.md` holds the complete table of all 273 hooks with arguments, returns,
defaults, and `CONFIG` guards.


## Patterns

Each pattern below is complete enough to paste into a module and adapt.

### Deny by absolute path

`file_open` receives one argument, and `file:path()` can fail, so handle the
`nil` before matching. Use `file:path()` rather than `dentry:path()` because
only the former is mount-qualified.

```lua
local errno = require("errno")

function M.file_open(file)
  local path = file:path()
  if path == "/etc/shadow" then
    return false, errno.EPERM
  end
  return true
end
```

Returning `true` is optional here — falling off the end gives the same
verdict — but it documents the intent, and it does not stop later modules from
running, because `0` is the hook's default.

### Label a task, then check the label

`bprm_committed_creds` is a void hook: it cannot deny, but it is the right place
to classify a process once its new credentials are committed. `current` cannot
carry a label (writes to it are silently dropped), and `file_open` receives no
task argument, so store the classification in a shared dict keyed by the task's
tgid — `current:pids()` gives you that tgid in either hook. Labels must be
booleans or numbers, so map role names to codes in Lua.

```lua
local ROLE = { untrusted = 1, service = 2 }

function M.bprm_committed_creds(bprm)
  local exe = bprm:executable()
  if exe and exe:path() == "/usr/bin/nginx" then
    local _, tgid = current:pids()
    shared.roles:set(tgid, ROLE.service)
  end
end

function M.file_open(file)
  local _, tgid = current:pids()
  if shared.roles:get(tgid) == ROLE.service then
    return true
  end
end
```

The label is private to your module. Clear it in a `task_free` hook, or the
`roles` dict fills as tgids are reused over the system's lifetime.

### Count events in a shared dict

A per-object label lives on one kernel object; `shared` is system-wide. Use
`incr` for a read-modify-write, since another CPU can change the value between a
`get` and a `set`. Keep the key space bounded — a dict holds 1024 entries and
never evicts.

```lua
function M.socket_connect(sock, address)
  local stats = shared.counters
  stats:incr("connect", 1)
end
```

### Fail closed

An error inside a hook leaves the hook's default verdict, which is normally
"allow". When a check must deny on its own bugs, run the fallible part under
`pcall()` and choose the verdict explicitly.

```lua
local errno = require("errno")

local function classify(file)
  return file:xattr("security.mypolicy") == nil
end

function M.file_open(file)
  local ok, allowed = pcall(classify, file)
  if not ok then
    return false, errno.EACCES
  end
  return allowed
end
```

### Record a decision for userspace

`audit.log()` emits a record through the kernel audit subsystem. It returns
`false` when audit is disabled, and it raises on a malformed table, so build the
table with fixed keys.

```lua
local audit = require("audit")
local errno = require("errno")

function M.inode_unlink(dir, dentry)
  local pid, tgid = current:pids()
  if dentry:path() == "/var/log/audit/audit.log" then
    audit.log({ op = "unlink_denied", pid = pid, tgid = tgid })
    return false, errno.EPERM
  end
  return true
end
```

### Read bytes out of a packet

`skb:read(off, len)` counts `off` from `skb->data`, whose protocol layer depends
on the hook, so anchor offsets to the hook you are in. There is no `bit`
library; combine bytes arithmetically. `skb:read()` raises on a missing or
non-numeric argument, so pass literal numbers.

```lua
local errno = require("errno")

function M.netlink_send(sk, skb)
  local hdr = skb:read(0, 4)
  if not hdr then
    return true                          -- too short to judge
  end
  local hi, lo = string.byte(hdr, 3, 4)  -- 16-bit big-endian field
  if hi * 256 + lo == 0x10 then
    return false, errno.EACCES
  end
  return true
end
```

### Handle arguments that may be absent

Some hooks omit an argument rather than passing a placeholder — `socket_bind`,
`socket_connect` and `sctp_bind_connect` drop the `sockaddr` when the supplied
`addrlen` is too short. Check before indexing, or the resulting error will fail
open.

```lua
function M.socket_connect(sock, address)
  if not address then
    return true
  end
  local family, addr, port = address:addrs()
  if family ~= "inet" and family ~= "inet6" then
    return true
  end
  return port ~= 23
end
```

### Restrict a capability check to one namespace

Pass capabilities as constants from the `capability` library. A misspelled
string name silently resolves to `CAP_CHOWN`, which usually makes the check
pass.

```lua
local capability = require("capability")
local errno = require("errno")

function M.sb_mount(dev_name, path, type, flags, data)
  if not current:capable(current:userns(), capability.CAP_SYS_ADMIN) then
    return false, errno.EPERM
  end
  return true
end
```


## Pitfalls

These are the mistakes that produce a policy which loads cleanly, logs nothing,
and does not do what you meant.

### A misspelled hook name is silently ignored

A table key that matches no hook name is logged as `field '<key>' is unknown`
and dropped (`security/lua/lsm.c:1084`). The module still registers, with that
hook simply absent. After loading a policy, confirm the hook count:

```sh
cat /sys/kernel/security/lua/modules   # the nlsm column
```

### `return 0` does not deny

On an int-returning hook a single non-boolean result is ignored and the default
applies (`security/lua/lsm_defs.h:99`). `return 0`, `return -1` and
`return errno.EPERM` are all silently "allow". Only these forms decide:

```lua
return true                     -- allow
return false                    -- deny with -EPERM
return false, errno.EACCES      -- deny with -EACCES
return nil, errno.EACCES        -- deny with -EACCES
```

### `false` does not mean deny on every hook

Four hooks use the boolean convention where `false` becomes `0`, not `-EPERM`,
and two more accept a boolean-or-errno pair. On those, a plain `return false`
means something different from what it means elsewhere. Check the hook's
`Returns` column in `HOOKS.md` before writing the check.

### An error in your policy allows the operation

A raised Lua error is logged and the hook falls back to its default, which is
`0` for most hooks. Indexing a `nil` argument, calling a method on the wrong
object type, or arithmetic on a `nil` all fail open. Wrap anything that can
fail in `pcall()` and decide the verdict yourself.

### A misspelled capability name resolves to `CAP_CHOWN`

The name-to-capability lookup returns `0` rather than an error for an
unrecognised string (`security/lua/auxlib.c:491`), and `0` is `CAP_CHOWN`. A
check written as `cred:has_cap("CAP_SYS_ADMIN")` with a typo therefore tests
something entirely different and usually passes. Use the `capability`
library's constants so a typo is a `nil` you notice.

### Storing a kernel object for later use reads freed memory

Every object a hook hands you — `file`, `inode`, `task`, `sock`, `skb`, ... —
wraps a raw kernel pointer with no lifetime marker. It is valid for the
duration of that hook call only. A dict cannot hold one (values are limited to
booleans, numbers and light userdata), so the way policies get this wrong is a
module-level variable or an upvalue: assign the object in one hook, touch it in
a later one, and you dereference freed memory. `skb:read()` on a stale object
walks freed page pointers. Extract the scalars you need (a pid, an inode
number, a boolean) and store those instead.

### Labels cannot be strings

The key/value store accepts booleans, numbers, and light userdata. A string
value is rejected with `-EINVAL`, and through the assignment sugar that
rejection is invisible:

```lua
file.role = "admin"    -- silently does nothing
file.role = 2          -- works; keep the name->number map in Lua
```

Use the method form (`file:kvcache_set(...)`) when you need to know whether a
write succeeded.

### `current` cannot carry labels

Labels attach only to objects a hook passes as arguments (and to constructor
results). `current` is built without the module binding
(`newtask_nomain`, `security/lua/lsm.c:685`), so a write through it is dropped
with `-ESRCH` and a read returns nothing — silently, since the sugar form hides
the error. `current.trusted = true` looks like it works and does not. Its
methods (`current:pids()`, `current:comm()`) are unaffected. To track the
acting task across hooks, key a `shared` dict by `current:pids()`'s tgid, as in
[Label a task, then check the label](#label-a-task-then-check-the-label).

### An unbounded key space fills a dict forever

Each dict holds `CACHE_CAPACITY` (1024) entries, never grows, and never evicts.
Keying on a pid, an inode number, or a port means the dict fills and then every
new key fails with `-ERANGE` for the lifetime of the module. Key on something
bounded, or delete entries explicitly with `nil` when you are done.

### Indexing `current` or `shared` at chunk top level fails the load

`module_load()` installs both in the per-module environment before it runs your
chunk (`security/lua/lsm.c:685`, `:688`), so a per-VM load does see them at the
top level. Registration does not: it runs the chunk against the plain global
environment (`security/lua/lsm.c:986`), where both are `nil`. Reading a `nil` is
harmless, but indexing one raises, and that error fails the load with no module
registered. Touch them only inside hook functions.

### `require()` is not optional

The built-in libraries are registered in `_LOADED` but not installed as
globals, so a bare `errno.EPERM` is an index into `nil`. Require every library
you use at the top of the chunk.

### `dentry:path()` is not an absolute path

`file:path()` renders through `d_path`, so it is mount-qualified and suitable
for matching absolute paths. `dentry:path()` and `tostring(path)` render
through `dentry_path`, which has no mount prefix. A rule written against
`dentry:path()` and tested on the root mount will not behave the same inside a
container or on a bind mount.

### Selector arguments drop the first name when you pass several

`inode:mode()`, `file:fmode()`, `cred:securebits()` and `vma:prot()` read their
name list from argument 2 only when exactly one name follows the receiver; with
two or more the first argument is consumed as the combining boolean and dropped
from the list, so `inode:mode("suid", "woth")` tests only `"woth"`. Pass that
boolean yourself whenever you list two or more names: `true` for all-of, `false`
for any-of. The lone-boolean forms are traps of their own, and not the same trap
on every method: `inode:mode(true)`, `file:fmode(true)` and
`cred:securebits(true)` return `true` for every object, because an empty mask
compares equal to itself, whereas `vma:prot(true)` **raises**, because the
boolean reaches `luaL_checkoption` (`security/lua/lua_mm.c:107`). None of them
is a usable probe; call `vma:wx()` or read the no-argument table instead.

### `skb:read()` raises on a missing argument

Out-of-range offsets and lengths return `nil`, but a missing or non-numeric
argument goes through `luaL_checkinteger` and raises — which, per the rule
above, allows the operation. Also, `off` is relative to `skb->data`, whose
protocol layer differs per hook, and `skb:len()` counts from there too, so it
is not a payload length.

### 86 hooks receive an argument that is always `nil`

Several hooks are wired up with `TODO` placeholders, and 23 of them receive no
usable argument at all. A policy written against one of those arguments will
never see data. Check `HOOKS.md` before choosing a hook.

### Integer arithmetic, and no `bit` library

Numbers are 64-bit integers in this build, so `/` truncates and there is no
float behaviour to rely on. Extract bytes with `string.byte` and combine them
with multiplication and addition.

### One denial ends the chain

Modules run in registration order and the first non-default result stops the
rest. A module that returns `true` does not stop anything, because `true`
equals the default; a module that denies prevents later modules from ever
seeing the call. Load order is therefore policy.
