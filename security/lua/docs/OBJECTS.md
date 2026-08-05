# Lua-LSM Object Reference

The object types a hook hands your policy. See `API.md` for the module format, execution model, hook contract, and per-object storage rules, and `LIBRARIES.md` for the built-in libraries.


Hooks hand your policy userdata objects that wrap kernel structures. Three
rules apply to all of them:

- **They are valid only inside the hook call that produced them.** They hold
  raw kernel pointers with no lifetime marker. Keeping one in a module-level
  variable and using it in a later hook reads freed memory.
- **Nothing is memoized.** Every method call re-reads the kernel structure, so
  two calls in one hook can disagree if the field changed underneath you.
- **Every object carries `type()` and label storage.** `obj:type()` returns the
  type name, and any key that is not a method routes to the per-object
  key/value store described in
  [Per-object storage](API.md#per-object-storage-and-shared-dicts). Methods are
  looked up first, so never name a label after a method.

In the tables below, `On failure` uses a fixed vocabulary: `raises` means a Lua
error (which, unhandled, lets the operation through), `nil` means a plain nil
return, `nil, errno` means a nil plus a positive errno number, and
`nil, errname` means a nil plus an errno *name string*, which carries a leading
minus such as `"-ENAMETOOLONG"`.

### `task`

A `task` wraps a `struct task_struct`, which is a single *thread* rather than a
process. You get one as a hook argument (`task_kill`, `ptrace_access_check`,
`task_setnice`, ...), from `kernel.task_from_pid()`, or from `current` inside a
hook body. It is a blob type, so it also carries a per-task key/value cache.

| Method | Arguments | Returns | On failure |
|---|---|---|---|
| `task:pids()` | none | 2 integers: `pid` (thread id), then `tgid` (thread group id) | raises |
| `task:cred()` | none | 1 `cred` | raises |
| `task:userns()` | none | 1 `userns` | raises |
| `task:comm()` | none | 1 string, at most 15 characters | raises |
| `task:nr_threads()` | none | 1 integer: threads in the thread group | raises |
| `task:group_leader()` | none | 1 `task` (`self` when it already is the leader) | raises |
| `task:thread_group_leader()` | none | 1 boolean | raises |
| `task:same_thread_group(other)` | `other`: `task` | 1 boolean | raises |
| `task:same_group_ptracer(tracer)` | `tracer`: `task` | 1 boolean: receiver is traced by `tracer`'s thread group | raises |
| `task:is_idle()` | none | 1 boolean: per-CPU swapper task | raises |
| `task:exe_file()` | none | 1 `file` owning an `fput` reference you must release with `file:fput()` | `nil, "busy"` when `task->alloc_lock` is held; `nil` when there is no exe file |
| `task:exepath()` | none | 1 string | `nil, "busy"` for a target other than `current` whose `alloc_lock` is held; `nil` when there is no mm or no exe file; `nil, errname` from path resolution |
| `task:cmdline()` | none | 1 string: full argv, NUL-separated fields joined with spaces | `nil` |
| `task:capable(cap [, opt...])` | `cap`: integer or capability name; `opt`: `"noaudit"`, `"insetid"` | 1 boolean | raises |
| `task:capable(ns, cap [, opt...])` | `ns`: `userns`; `cap` as above | 1 boolean | raises |
| `task:capable(other, cap [, opt...])` | `other`: `task`; `cap` as above | 1 boolean | raises |
| `task:is_descendant(parent)` | `parent`: `task`, or a number treated as a vpid | 1 boolean | raises |
| `task:pid_alive()` | none | 1 boolean: the task still has a pid attached | raises |
| `task:type()` | none | 2 values: `"task"`, `true` | raises |
| `task:kvcache_get(key)` | `key`: string | 1 value, or `nil` when unset | raises on a non-string key |
| `task:kvcache_set(key, value)` | `key`: string; `value`: boolean, number, lightuserdata, or `nil` to delete | `true` | `nil, errno` |
| `task:kvcache_incr(key [, delta])` | `key`: string; `delta`: number, default `1` | 1 number: the new value | `nil, errno` |
| `tostring(t)` | none | 1 string: `task: '<comm>'` | never fails |

**Notes.**

- **Object validity.** Every kernel object in this API (`task`, `cred`,
  `userns`, `vma`, `ipc`, `msgmsg`, `bdev`, `key`, `perfevent`) is a thin
  wrapper around a raw kernel pointer with no lifetime marker attached. A
  hook-supplied object is valid only inside the hook invocation that produced
  it. Keeping one in a module-level variable — a global assignment, which the
  runtime warns about but still performs — and using it from a later hook reads
  freed memory. A shared dict cannot hold one at all, since it accepts only
  booleans, numbers and lightuserdata. Keep per-object state in the kvcache
  instead, which lives in the kernel object's security blob and outlives the
  hook.
- A few results own a reference and stay dereferenceable after the hook
  returns: `kernel.task_from_pid()`, `task:userns()`, `cred:userns()`, and the
  `file` objects from `task:exe_file()` and `vma:file()`. Those two `file`
  objects each take their own `fput` reference
  (`security/lua/lua_kernel.c:361`, `security/lua/lua_mm.c:51`), so you **must**
  release them with `file:fput()`; skipping it leaks a file reference on every
  call. Even so, a referenced `task` can be reaped; check `task:pid_alive()`
  before acting on a `task` you obtained earlier.
- `task:group_leader()` returns `self` unchanged when the receiver already is
  the group leader, and otherwise a borrowed, hook-scoped object even if the
  receiver owned a reference. Do not carry the result past the hook.
- **Namespaces.** `task:pids()` returns the raw `task_struct` fields, which are
  ids in the *initial* pid namespace. `kernel.task_from_pid()` and the numeric
  form of `task:is_descendant()` take a *vpid*, resolved in the pid namespace of
  `current`. These are opposite directions, so feeding a `task:pids()` result
  back into `task:is_descendant()` is wrong inside a container.
- `task:capable()` uses the target task's own cred and, unless you pass a
  `userns` or another `task`, that cred's `user_ns` as the namespace. It is the
  `cap_capable()` bit test walking the user_ns ancestry against
  `cap_effective`; it does not call `security_capable()`, does not consult other
  LSMs, and emits no capability audit record, so `"noaudit"` and `"insetid"`
  have no observable effect.
- **Pass capability constants, never hand-typed strings.** A capability name
  that does not match the internal table leaves the resolved value at `0`,
  which is a valid capability — `CAP_CHOWN` — so
  `task:capable('sys_adminx')` silently tests `CAP_CHOWN` instead of raising
  (`security/lua/auxlib.c:491`). Almost every task has `CAP_CHOWN` denied and
  many have it granted, so a typo turns a deny rule into an allow rule with no
  diagnostic anywhere. Always use the integer constants exported by the
  `capability` library.

  ```lua
  local capability = require('capability')
  local errno = require('errno')

  function M.task_kill(p, info, sig, cred)
    if p:capable(capability.CAP_KILL) then
      return true
    end
    return false, errno.EPERM
  end
  ```

- `task:comm()` reads `task->comm` without taking `task_lock()`, so a
  concurrent `prctl(PR_SET_NAME)` or exec can be observed torn. `comm` is
  15 characters and freely settable by the task itself; never use it as a
  security identity. `task:exepath()` and `task:cmdline()` are also
  attacker-influenced, and `cmdline` is fully attacker-controlled.
- `task:cmdline()` takes `mmap_lock` and can fault and sleep. Do not call it
  from an atomic hook or between `kernel.rcu_read_lock()` and
  `kernel.rcu_read_unlock()`. It also allocates a page on every call, so it is
  too expensive for a hot hook.
- `task:exepath()` resolves through `d_path()` against the mount namespace and
  root of `current`, not of the target task, and the result may carry a
  `" (deleted)"` suffix. Treat it as a diagnostic string, and match on inode
  identity when you need a stable rule.
- `task:exe_file()` returns `nil, "busy"` — a plain string, not an errno name —
  when the target's `alloc_lock` is already held, and `task:exepath()` does the
  same for every target except `current`: that case takes a separate branch with
  no `alloc_lock` check at all (`security/lua/lua_kernel.c:371`), so
  `current:exepath()` never reports `"busy"`. Where `"busy"` can appear it is
  not retryable inside the same hook, so pick a fail-open or fail-closed answer
  explicitly rather than falling through.
- `task:is_descendant()` normalises both sides to their thread group leaders and
  then walks the `real_parent` chain, so **a task is its own descendant**, and
  `ptrace` reparenting does not change the answer. The walk crosses pid
  namespace boundaries and stops only at pid 0.
- The kvcache holds at most 1024 keys per object, shared by all policy modules,
  and `nil, errno` reports `"-ERANGE"` at that cap. The second result is the
  errno *name* as a string and it carries a leading minus (`"-ERANGE"`,
  `"-ENOMEM"`, `"-ESRCH"`, `"-EINVAL"`), not a number, so it does not compare
  equal to an `errno` library constant. A task with no lua-lsm security blob
  yields `"-ESRCH"` on writes and no value on reads. `t.foo` and `t.foo = v` are
  sugar for `kvcache_get`/`kvcache_set`, except that `t.foo` first searches the
  method table, so a key named after a method returns the method.
- Numbers are 64-bit integers in this build
  (`include/linux/luaconf.h:502`), so pids, thread counts and inode numbers are
  exact with no floating-point rounding. Division truncates: `7 / 2` is `3`.

### `cred`

A `cred` wraps a `struct cred`: the uid/gid set, the four capability sets, the
securebits and the owning user namespace. You get one as a hook argument
(`task_fix_setuid` receives `new, old`; `userns_create` receives one; many hooks
pass a subjective cred) or from `task:cred()`. It is a blob type with a per-cred
kvcache.

| Method | Arguments | Returns | On failure |
|---|---|---|---|
| `cred:uids()` | none | 4 integers in order: `uid`, `euid`, `suid`, `fsuid` | raises |
| `cred:gids()` | none | 4 integers in order: `gid`, `egid`, `sgid`, `fsgid` | raises |
| `cred:cap_eip()` | none | 3 `cap` objects in order: effective, inheritable, permitted | raises |
| `cred:cap_eip(e [, i [, p]])` | `cap` objects or `nil` to skip a field | 1 value: `self` | raises when an argument is neither a `cap` nor `nil`; raises on more than 4 arguments |
| `cred:cap_bset()` | none | 1 `cap`: the bounding set | raises |
| `cred:cap_bset(cap)` | `cap`: `cap` object, `nil` not accepted | 1 value: `self` | raises |
| `cred:cap_ambient()` | none | 1 `cap`: the ambient set | raises |
| `cred:cap_ambient(cap)` | `cap`: `cap` object, `nil` not accepted | 1 value: `self` | raises |
| `cred:securebits()` | none | 1 table: set bit names mapped to `true` | raises |
| `cred:securebits(name)` | `name`: securebit name, number, or table of names | 1 boolean | raises only on a bad receiver |
| `cred:securebits(and_flag, name...)` | `and_flag`: `true` for all-of, anything else for any-of | 1 boolean | raises only on a bad receiver |
| `cred:userns()` | none | 1 `userns` | raises |
| `cred:capable(cap [, opt...])` | as `task:capable()`, with this cred as the subject | 1 boolean | raises |
| `cred:type()` | none | 2 values: `"cred"`, `true` | raises |
| `cred:kvcache_get(key)` | `key`: string | 1 value, or `nil` when unset | raises on a non-string key |
| `cred:kvcache_set(key, value)` | as `task:kvcache_set()` | `true` | `nil, errno` |
| `cred:kvcache_incr(key [, delta])` | as `task:kvcache_incr()` | 1 number | `nil, errno` |
| `tostring(c)` | none | 1 string: `cred: <0xptr>` | never fails |

**Notes.**

- **Namespaces.** `cred:uids()` and `cred:gids()` return raw `kuid_t`/`kgid_t`
  values, which are ids in the *initial* user namespace. No `from_kuid()`
  translation into `cred->user_ns` or into the caller's namespace happens. Inside
  a user-namespaced container, uid 0 as seen by the container appears here as
  the host-side mapped id (for example 100000), so `uid == 0` does not mean
  "container root". Test `cred:userns():is_initial()` alongside the id, or
  compare against the mapped range you provisioned.
- Supplementary groups are not exposed; `cred:gids()` covers only the four
  primary gids.
- `cred:cap_eip()` returns effective, inheritable, permitted — E, I, P — not the
  order the name suggests for the last two. The setter assigns from the same
  positions, and `nil` in any position leaves that field alone.
- The setter forms write directly into the `struct cred` with no locking and no
  RCU grace period. That is only legitimate for the *new*, not-yet-committed
  cred a hook hands you first (`task_fix_setuid`'s `new`,
  `cred_prepare`'s `new`). Writing to a committed cred — anything from
  `task:cred()`, or the `old` argument — mutates live credentials behind the
  kernel's back. Nothing in the API stops you.
- **Selector arguments on `securebits()`.** The name list starts at argument 2
  only when there are exactly two arguments; with three or more it starts at
  argument 3. So `cred:securebits('noroot', 'keep_caps')` silently drops
  `'noroot'` and tests only `'keep_caps'`. Whenever you list two or more names,
  pass the combining boolean first.

  ```lua
  local errno = require('errno')

  function M.task_fix_setuid(new, old, flags)
    -- correct: explicit and_flag, then the names
    if new:securebits(true, 'noroot', 'no_setuid_fixup') then
      return true
    end
    return false, errno.EPERM
  end
  ```

- `cred:securebits(true)` always returns `true`. A lone boolean resolves to an
  empty bit mask, and the all-of branch then compares `0 == 0`. It tells you
  nothing about the cred, so never write it as a shorthand for "any securebit
  set" — call `cred:securebits()` and inspect the table instead.
- Unknown securebit names are silently ignored rather than raising, and matching
  is case-insensitive. Valid names: `noroot`, `no_setuid_fixup`, `keep_caps`,
  `no_cap_ambient_raise`, `exec_restrict_file`, `exec_deny_interactive`. The
  corresponding `*_LOCKED` bits are not exposed, and there is no setter.
- A number passed as a selector is OR-ed into the mask raw, with no validation,
  so a stray numeric argument can match bits you did not name.
- `cred:capable()` shares the capability-name trap described in the `task`
  section: pass `capability.CAP_*` constants, not strings.
- `cred:userns()` returns an object holding its own `get_user_ns()` reference,
  so it remains valid after the hook returns, unlike the `cred` it came from.
- `task:cred()` takes a cred reference that this API never releases. Prefer the
  `cred` objects a hook already passes you, and call `task:cred()` only when
  there is no alternative.

### `userns`

A `userns` wraps a `struct user_namespace`. You get one from `cred:userns()`,
`task:userns()`, or a hook argument. It is a func type: no kvcache, and
assigning a field to it raises a Lua error.

| Method | Arguments | Returns | On failure |
|---|---|---|---|
| `userns:is_initial()` | none | 1 boolean: this is the host `init_user_ns` | raises |
| `userns:level()` | none | 1 integer: nesting depth, `0` for the initial namespace | raises |
| `userns:owner_uid()` | none | 1 integer: creator uid | raises |
| `userns:owner_gid()` | none | 1 integer: creator gid | raises |
| `userns:inum()` | none | 1 integer: the namespace's proc inode number | raises |
| `userns:same(other)` | `other`: `userns` | 1 boolean: pointer identity | raises |
| `userns:type()` | none | 2 values: `"userns"`, `false` | raises |
| `tostring(ns)` | none | 1 string: `userns: <inum = N, level = N>` | never fails |

**Notes.**

- **Namespaces.** `owner_uid()` and `owner_gid()` are raw `kuid_t`/`kgid_t`
  values — kernel-global ids, the same convention as `cred:uids()`. They are not
  translated into the parent namespace's view, so compare them against
  host-side ids.
- `inum()` matches what userspace reads from `/proc/<pid>/ns/user`
  (`user:[<inum>]`), which makes it the right value to log or to key a rule on.
  It is unique while the namespace lives but may be reused afterwards, so do not
  treat a stored inum as permanently identifying.
- `level()` is capped at 32 by the kernel. A non-zero level means the subject
  sits inside at least one user namespace, which is the cheapest container test
  available here.
- `userns:same(other)` raises when `other` is missing or is not a `userns`;
  there is no nil-tolerant form. Objects from `cred:userns()` and
  `task:userns()` own a reference and outlive the hook; a `userns` passed in by
  a hook does not.

  ```lua
  local errno = require('errno')

  function M.userns_create(cred)
    local ns = cred:userns()
    if ns:level() >= 2 then
      return false, errno.EPERM   -- no nesting past one level
    end
    return true
  end
  ```

### `vma`

A `vma` describes one memory mapping. The only hook that produces one is
`file_mprotect`, whose arguments are `(vma, reqprot, prot)` — the two prot masks
are also available as plain numbers. This type does not use the shared object
machinery: there is no `type()` method, no kvcache, and assigning a field raises
a Lua error.

| Method | Arguments | Returns | On failure |
|---|---|---|---|
| `vma:file()` | none | 1 `file` for a file-backed mapping, owning an `fput` reference you must release with `file:fput()` | `nil` for an anonymous mapping |
| `vma:start()` | none | 1 number: start virtual address | raises |
| `vma:finish()` | none | 1 number: exclusive end virtual address | raises |
| `vma:size()` | none | 1 number: bytes, always page-aligned | raises |
| `vma:prot()` | none | 1 table: `read`/`write`/`exec` keys set to `true` | raises |
| `vma:prot(name)` | `name`: `"read"`, `"write"`, `"exec"`, or a number | 1 boolean | raises on an unknown name or a non-number, non-string |
| `vma:prot(and_flag, name...)` | `and_flag`: `true` for all-of, anything else for any-of | 1 boolean | raises on an unknown name |
| `vma:reqprot([and_flag,] ...)` | as `vma:prot()` | same shapes, tested against the requested prot | as `vma:prot()` |
| `vma:was([and_flag,] ...)` | as `vma:prot()` | same shapes, tested against the pre-`mprotect` prot | as `vma:prot()` |
| `vma:mapping()` | none | 1 string: `"shared"` or `"private"` | raises |
| `vma:mapping(which)` | `which`: `"private"` or `"shared"` | 1 boolean | raises on any other value |
| `vma:file_backed()` | none | 1 boolean: the mapping has a backing file | raises |
| `vma:anonymous()` | none | 1 boolean: the mapping has no `vm_ops` | raises |
| `vma:heap()` | none | 1 boolean: the mapping lies inside the brk heap | raises |
| `vma:stack()` | none | 1 boolean: initial process stack, or `current`'s stack | raises |
| `vma:file_cow()` | none | 1 boolean: file-backed and already has COW anon pages | raises |
| `vma:gaining_exec()` | none | 1 boolean: this call adds `PROT_EXEC` | raises |
| `vma:gaining_write()` | none | 1 boolean: this call adds `PROT_WRITE` | raises |
| `vma:write_to_exec()` | none | 1 boolean: was writable and is now gaining exec | raises |
| `vma:implied_exec()` | none | 1 boolean: exec granted although not requested | raises |
| `vma:wx()` | none | 1 boolean: resulting prot has both write and exec | raises |
| `tostring(v)` | none | 1 string: `vma: <0xptr>` of the snapshot | never fails |

**Notes.**

- **A `vma` is a snapshot, not a live view.** The addresses, prot masks and the
  `anonymous`/`shared`/`heap`/`stack`/`file_cow` booleans are all copied when the
  object is created; the kernel `vm_area_struct` is not retained. Every method
  therefore answers about the state at hook entry, and re-reading a method later
  in the same hook cannot show a change. Because nothing is retained, the
  userdata itself is safe to read after the hook returns — but it tells you
  nothing new, so there is no reason to keep it.
- `vma:prot()` reports the *effective* prot after
  `arch_calc_vm_prot_bits()` and personality adjustments; `vma:reqprot()`
  reports exactly what the caller passed to `mprotect(2)`; `vma:was()` reports
  the protection reconstructed from `vm_flags` before this call. A W-to-X rule
  needs `was()` and `prot()`, not `reqprot()`.
- **Selector arguments.** As with `cred:securebits()`, the name list starts at
  argument 2 only when there are exactly two arguments, and at argument 3
  otherwise, so `vma:prot('read', 'exec')` silently ignores `'read'`. Pass the
  combining boolean whenever you list two or more names.
- `vma:prot(true)` **raises**: the boolean reaches the option check and is
  rejected as an invalid option. This differs from `cred:securebits(true)`,
  which returns a meaningless `true`. Neither form is useful; write
  `vma:prot(true, 'write', 'exec')` when you mean "both bits set", or
  `vma:wx()`.
- Prot and mapping names are case-sensitive here: `vma:prot('READ')` raises,
  even though `cred:securebits('NOROOT')` is accepted. Valid prot names are
  `read`, `write`, `exec`; valid mapping names are `private`, `shared`.
- A number passed as a prot selector is OR-ed in unvalidated, so a numeric
  `PROT_*` value works but is not checked against the three known bits.
- `heap()` and `stack()` were evaluated against **`current`** at snapshot time.
  For a hook acting on another process's mm, `stack()` answers "is this the
  current task's stack", not "is this the owner's stack".
- `vma:anonymous()` is not the negation of `vma:file_backed()`; special mappings
  such as vdso have `vm_ops` but no file, so both can be false.
- `vma:file()` returns a fresh reference on each call and the resulting `file`
  object is valid past the hook, so you **must** release it with `file:fput()`.
  `file_mprotect` is a hot path, and a missed release leaks one file reference
  per call. `tostring(v)` prints the address of the snapshot userdata, not of
  the kernel mapping, so it is useless as a mapping identity — use
  `vma:start()` and `vma:finish()`.
- Addresses are exact: numbers are 64-bit integers in this build
  (`include/linux/luaconf.h:502`), so no rounding occurs, but an address above
  `2^63` would print as a negative number. User mappings stay below that.

  ```lua
  local errno = require('errno')
  local audit = require('audit')

  function M.file_mprotect(vma, reqprot, prot)
    if vma:write_to_exec() and not vma:file_backed() then
      audit.log{ op = 'wx', addr = vma:start(), size = vma:size() }
      return false, errno.EACCES
    end
    return true
  end
  ```

### Label-only objects: `ipc`, `msgmsg`, `bdev`, `key`, `perfevent`

These five types wrap `struct kern_ipc_perm`, `struct msg_msg`,
`struct block_device`, `struct key` and `struct perf_event`. They expose **no
field accessors at all** — no uid, gid, mode, key id, device number, message
size or event attributes. What you can do with one is identify it, print it,
and, for `ipc`, `msgmsg` and `bdev`, hang your own annotations on it through the
kvcache.

| Method | Arguments | Returns | On failure |
|---|---|---|---|
| `obj:type()` | none | 2 values: the type name string, and `true` for `ipc`/`msgmsg`/`bdev`, `false` for `key`/`perfevent` | raises |
| `tostring(obj)` | none | 1 string: `<type>: <0xptr>` | never fails |
| `obj:kvcache_get(key)` | `key`: string | 1 value, or `nil` when unset | raises on a non-string key |
| `obj:kvcache_set(key, value)` | `key`: string; `value`: boolean, number, lightuserdata, or `nil` to delete | `true` | `nil, errno` |
| `obj:kvcache_incr(key [, delta])` | `key`: string; `delta`: number, default `1` | 1 number: the new value | `nil, errno` |

**Notes.**

- The three kvcache rows and the field sugar (`obj.foo`, `obj.foo = v`) exist
  only on `ipc`, `msgmsg` and `bdev`, which are blob types. `key` and
  `perfevent` are func types: they have `type()` and `tostring()` and nothing
  else, and assigning a field to one raises a Lua error.
- Use the kvcache to carry a label forward across hooks on the same kernel
  object — for example marking a message queue the first time a privileged task
  touches it and checking that mark on later permission hooks. The mark lives in
  the object's security blob, so it survives the hook that set it even though
  the wrapper object does not.

  ```lua
  local errno = require('errno')

  function M.ipc_permission(ipcp, flag)
    if ipcp.privileged then
      return true
    end
    ipcp:kvcache_incr('touches')
    return true
  end
  ```

- Reads return no value and writes return `nil, "-ESRCH"` when the kernel object
  carries no lua-lsm security blob. As elsewhere, the second result is an errno
  *name* string with a leading minus, not a number, and the dict holds at most
  1024 keys per object across all modules.
- `key` and `perfevent` are effectively unreachable in a normal build: the key
  hooks are unsupported under `CONFIG_KEYS`/`CONFIG_KEY_NOTIFICATIONS` and the
  `perf_event_*` hooks are unsupported under `CONFIG_PERF_EVENTS`
  (`security/lua/lsm.h:54`). Check `kernel.lsm_funcs()` before writing a policy
  that depends on either.

### `file`

A `file` wraps a `struct file *`. You get one from the `file_*` hooks
(`file_permission`, `file_open`, `file_ioctl`, `file_release`, ...), from
`mmap_file`, from `binprm:executable()` / `binprm:interpreter()` /
`binprm:file()`, and from `fs.filp_open()`. It is the only object in this
module that can render a mount-qualified, namespace-visible path.

| Method | Arguments | Returns | On failure |
|---|---|---|---|
| `file:dentry()` | none | `dentry` | no failure path (see notes) |
| `file:inode()` | none | `inode` | no failure path (see notes) |
| `file:xattr(name)` | `name`: full attribute name, e.g. `"security.selinux"` | attribute value as a binary-safe string | nothing at all when the inode has no xattr support; `nil` when the value is empty; `nil, errno` (positive) on a getxattr error; `raises` if `name` is not a string |
| `file:size()` | none | `size` in bytes | none |
| `file:fmode()` | none | table whose keys are the set flag names | none |
| `file:fmode(all, ...)` | `all`: boolean; then flag names (`"read"`, `"write"`, `"exec"`, `"opened"`, `"created"`), arrays of names, or raw bit numbers | `boolean` | unknown names are ignored, so you get `false` |
| `file:path()` | none | path string rendered by `d_path` | `nil, errname` (`"-ESRCH"`, `"-ENOENT"`, `"-ENAMETOOLONG"`, `"-ENOMEM"`) |
| `file:fput()` | none | nothing | `raises` unless the file came from `fs.filp_open()`, `task:exe_file()` or `vma:file()` |
| `file:type()` | none | `"file", true` | none |
| `file:kvcache_get(key)` | `key`: string | stored value, or `nil` if unset | `nil` (no values at all) when the file has no LSM blob |
| `file:kvcache_set(key, value)` | `key`: string; `value`: boolean, number, or light userdata (`nil` deletes the key) | `true` | `nil, errname`, or `nil, "unknown"` for an errno with no symbolic name |
| `file:kvcache_incr(key [, delta])` | `key`: string; `delta`: number, default `1` | the new number | `nil, errname` (`"-EINVAL"` if the stored value is not a number) |
| `tostring(file)` | none | `"file: '<path>'"` | `"file: <err = -ENAMETOOLONG>"` and similar |

**Notes.**

- **Validity.** Every object in this module is a bare kernel pointer with no
  refcount and no liveness marker (`security/lua/lua_object.h:23-30`). An
  object handed to a hook is valid only for the duration of that hook call.
  Storing a `file`, `dentry`, `inode`, `path`, `superblock`, `vfsmount`,
  `mntidmap`, `binprm`, or `fscontext` in a module-level variable or table and
  touching it from a later hook dereferences freed memory and oopses the
  kernel. The `shared` dict is not an escape hatch either: it stores only
  booleans, numbers, and light userdata, so an object value is rejected with
  `-EINVAL`. Carry *derived data* (a number, a boolean) across hooks, never
  the object. The exceptions are the `file` objects from `fs.filp_open()`,
  `task:exe_file()` and `vma:file()`, each of which holds an `fput` reference
  until `file:fput()` or garbage collection, and a dentry you explicitly
  `dget()`.
- **`file:path()` is the one to match against absolute paths.** It renders
  `d_path(&file->f_path)`, so it includes mount points and is resolved against
  `current->fs->root` — the *calling task's* chroot and mount namespace, which
  in a container is the container's view. Unlinked files get a `" (deleted)"`
  suffix, and a path outside `current`'s root comes back *relative*, without a
  leading `/`, so do not assume the first character is `/`. Pseudo
  filesystems render synthetic names such as `pipe:[12345]` or
  `anon_inode:[eventfd]`. Prefer `file:path()` over `dentry:path()` whenever
  the policy compares against absolute paths.
- **`file:path()` fails legitimately.** `current->fs` is NULL for kernel
  threads and exiting tasks, which yields `nil, "-ESRCH"`
  (`security/lua/auxlib.c:420-424`). Always branch on the `nil`, and decide
  explicitly whether an unresolvable path means allow or deny.
- **No truncation, but a hard ceiling.** Path rendering uses a 256-byte stack
  buffer and retries once with a `PATH_MAX` allocation; a longer path returns
  `nil, "-ENAMETOOLONG"` and a failed allocation returns `nil, "-ENOMEM"`. You
  never get a silently shortened path.
- **`file:xattr()` caps values at 128 bytes.** The read goes into a 128-byte
  on-stack buffer (`security/lua/lua_fs.c:26`), and there is no larger-buffer
  retry, so a longer value returns `nil, 34` (`ERANGE`). Values are returned
  with an exact length and may contain NUL bytes. The call reaches the
  filesystem through `__vfs_getxattr()` and **may sleep**, so keep it out of
  atomic and RCU hooks. Prefer `file:xattr()` over `dentry:xattr()` /
  `inode:xattr()` when you have a file: it derives the dentry/inode pair
  itself and cannot be given a mismatched pair.
- **`file:fmode(...)` selector form.** With no arguments you get a table of
  set flags. With exactly one argument it is treated as a flag selector, so
  `file:fmode("write")` works and means "any of". With two or more arguments
  the *first* one is consumed as the AND flag and skipped as a selector, so
  `file:fmode("read", "write")` tests only `"write"`. Always pass the boolean
  explicitly once you have two or more names: `file:fmode(true, ...)` for "all
  of", `file:fmode(false, ...)` for "any of". `file:fmode(true)` on its own
  returns `true` regardless of `f_mode`, so never use it as a probe.
- **Only 5 flag names exist**: `read`, `write`, `exec`, `opened`, `created`.
  Other `FMODE_*` bits have no name; pass a raw number if you need them.
  Unknown names are silently ignored rather than raising.
- **The `raw` file variant.** `file_alloc_security` and `file_free_security`
  hand you a restricted `file` object whose metatable is the raw one. It
  accepts only `kvcache_get`, `kvcache_set`, `kvcache_incr`, `type`, and
  `tostring` — every `fs`-module method, including `file:path()`, raises
  `method.file expected`. Treat those two hooks as blob bookkeeping only. The
  restricted `tostring` prints a kernel pointer.
- **`file:dentry()` and `file:inode()` have no NULL check**
  (`security/lua/lua_fs.c:259,266`). They always return an object, even when
  the underlying pointer is NULL, and the *next* method call on that object is
  what oopses. Unlike `dentry:backing_inode()`, they never return `nil`.
- **`file:fput()` works on the three reference-owning file objects** — those
  from `fs.filp_open()`, `task:exe_file()` and `vma:file()` — even though it
  appears on every file object; the check happens at call time and any other
  file raises. All three take their own `fput` reference
  (`security/lua/lua_kernel.c:361`, `security/lua/lua_mm.c:51`), so the policy
  **must** release each one or it leaks a file reference — and `vma:file()` sits
  on the `file_mprotect` hot path, where the leak is per `mprotect(2)` call.
  `fput()` is idempotent, and calling it makes the later `__gc` a no-op. Prefer
  explicit `fput()` because in-kernel Lua garbage collection is not prompt.
- **Nothing is memoized.** Each call re-reads the kernel struct, re-renders
  the path, or re-issues the getxattr. Three `file:path()` calls in one hook
  mean three renders and up to three `PATH_MAX` allocations. Bind the result
  to a local.
- The per-file kvcache dict is the right place to carry a *numeric* verdict
  from `file_open` to `file_permission`; strings cannot be stored.

```lua
local errno = require("errno")

function M.file_open(file)
  local path = file:path()
  if not path then
    return false, errno.EACCES
  end
  if path == "/etc/shadow" and file:fmode(false, "write", "exec") then
    return false, errno.EPERM
  end
  return true
end
```

### `dentry`

A `dentry` wraps a `struct dentry *`. It arrives from the `path_*` and
`inode_*` hooks, and from `file:dentry()`, `path:dentry()`, and
`superblock:root()`. It carries no mount, so it cannot describe a
namespace-visible path.

| Method | Arguments | Returns | On failure |
|---|---|---|---|
| `dentry:dget()` | none | the same `dentry` (for chaining) | none |
| `dentry:dput()` | none | nothing | none |
| `dentry:backing_inode()` | none | `inode`, or `nil` for a negative dentry | `nil` |
| `dentry:xattr(inode, name)` | `inode`: an `inode` object, mandatory; `name`: full attribute name | attribute value as a binary-safe string | nothing at all when the inode has no xattr support; `nil` when the value is empty; `nil, errno` (positive) on a getxattr error; `raises` on a wrong-typed `inode` or a non-string `name` |
| `dentry:path([raw])` | `raw`: boolean, default `false` | path string rendered by `dentry_path` (`dentry_path_raw` when `raw`) | `nil, errname` (`"-ENAMETOOLONG"`, `"-ENOMEM"`) |
| `dentry:type()` | none | `"dentry", false` | none |
| `tostring(dentry)` | none | `"dentry: '<path>'"` | `"dentry: <err = -ENOMEM>"` and similar |

**Notes.**

- **`dentry:path()` is filesystem-relative, not the path a user sees.** It
  renders `dentry_path()`, which walks up to the root of *that dentry's tree*
  with no mount prefix and no mount-namespace or chroot resolution
  (`security/lua/auxlib.c:462-465`). A file at `/etc/passwd` on a filesystem
  mounted at `/mnt` renders as `/etc/passwd`. For a policy that matches
  absolute paths, use `file:path()`; use `dentry:path()` only for
  within-filesystem comparisons or logging.
- **Deleted markers differ from `file:path()`.** `dentry:path()` splices
  `"//deleted"` into the result for an unlinked dentry, `dentry:path(true)`
  adds no marker at all, and neither ever produces the `" (deleted)"` suffix
  that `d_path` (and therefore `file:path()`) appends. Do not write one string
  test that expects both spellings.
- The `raw` argument is read with `lua_toboolean` and never raises: any truthy
  value selects `dentry_path_raw`.
- Buffering matches `file:path()`: 256-byte stack buffer, one `PATH_MAX`
  retry, error instead of truncation.
- **`dentry:xattr()` does not check that `inode` belongs to `dentry`**
  (`security/lua/lua_fs.c:77-84`). The pair you pass is used verbatim, so a
  mismatch is accepted and produces meaningless results. Prefer
  `file:xattr(name)` when a file is available; otherwise pass
  `dentry:backing_inode()` and handle its `nil`. The 128-byte cap, the
  `ERANGE` behaviour, and the sleeping requirement are the same as
  `file:xattr()`.
- **Reference counting is manual and unforgiving.** `dget()` takes a
  reference that nothing releases for you — there is no `__gc` for `dentry`,
  so an unmatched `dget()` on a hot path leaks dentries and can leave a
  filesystem unmountable. `dput()` does not verify that you took a reference
  first: calling it on a hook-supplied dentry drops the *caller's* reference
  and causes a use-after-free. Prefer touching hook-supplied dentries inline
  and calling neither.
- A `dentry` has no kvcache dict (`dentry:type()` reports `false`), so
  `dentry.foo` is always `nil` and `dentry.foo = 1` raises.
- Object validity is as described under `file`: a hook-supplied dentry dies
  with the hook.
- No method memoizes; each `path()` call re-walks the tree under
  `rename_lock`.

```lua
local errno = require("errno")

function M.path_unlink(dir, dentry)
  local inode = dentry:backing_inode()
  if inode and inode:mode(false, "suid", "sgid") then
    return false, errno.EPERM
  end
  return true
end
```

### `inode`

An `inode` wraps a `struct inode *`. The `inode_*` hooks pass it directly,
and you also get one from `file:inode()` and `dentry:backing_inode()`. It is
kvcache-backed, so it can hold per-inode policy state.

| Method | Arguments | Returns | On failure |
|---|---|---|---|
| `inode:ino()` | none | `i_ino` as an exact integer | none |
| `inode:xattr(dentry, name)` | `dentry`: a `dentry` object, mandatory; `name`: full attribute name | attribute value as a binary-safe string | nothing at all when the inode has no xattr support; `nil` when the value is empty; `nil, errno` (positive) on a getxattr error; `raises` on a wrong-typed `dentry` or a non-string `name` |
| `inode:size()` | none | `size` in bytes | none |
| `inode:filetype()` | none | one of `"sock"`, `"lnk"`, `"reg"`, `"blk"`, `"dir"`, `"chr"`, `"fifo"` | `nil` when `S_IFMT` matches nothing |
| `inode:filetype(name)` | `name`: one of the seven names, case-insensitive | `boolean` | `nil` for an unrecognised name, and `nil` if you pass a second argument; `raises` if `name` is not a string or number |
| `inode:mode()` | none | table whose keys are the set permission-bit names | none |
| `inode:mode(all, ...)` | `all`: boolean; then bit names, arrays of names, or raw numbers | `boolean` | unknown names are ignored, so you get `false` |
| `inode:ids()` | none | `uid, gid` | none |
| `inode:type()` | none | `"inode", true` | none |
| `inode:kvcache_get(key)` | `key`: string | stored value, or `nil` if unset | `nil` (no values at all) when the inode has no LSM blob |
| `inode:kvcache_set(key, value)` | `key`: string; `value`: boolean, number, or light userdata (`nil` deletes the key) | `true` | `nil, errname` (`"-ESRCH"` with no blob), or `nil, "unknown"` |
| `inode:kvcache_incr(key [, delta])` | `key`: string; `delta`: number, default `1` | the new number | `nil, errname` |
| `tostring(inode)` | none | `"inode: [<i_ino>]"` | none |

**Notes.**

- **`mode()` exposes permission bits only.** The 12 names are `suid`, `sgid`,
  `vtx`, `rusr`, `wusr`, `xusr`, `rgrp`, `wgrp`, `xgrp`, `roth`, `woth`,
  `xoth`. The `S_IFMT` type bits are not among them — use `filetype()`.
- **`inode:mode(...)` selector form** behaves exactly like `file:fmode(...)`:
  no arguments gives the table; a single argument is a selector, so
  `inode:mode("suid")` works and means "any of"; with two or more arguments
  the first is consumed as the AND flag and dropped from the selector list, so
  `inode:mode("suid", "woth")` silently tests only `"woth"`. Pass the boolean
  explicitly — `inode:mode(true, "rusr", "wusr")` for "all of",
  `inode:mode(false, "suid", "sgid")` for "any of". `inode:mode(true)` returns
  `true` for every inode, and `inode:mode(false)` and `inode:mode("typo")`
  return `false`, so none of those forms is a usable probe
  (`security/lua/lua_fs.c:209-216`).
- **The `mode()` table lists only set bits.** A clear bit is absent, never
  `false`, so test with `t.wusr` and do not infer clear bits from `next()` or
  `#`.
- **`filetype(name)` returns `nil`, not `false`, for a name it does not
  know**, and there is no `"unknown"` fallback. Both `if inode:filetype(x)`
  and `if not inode:filetype(x)` treat a typo as "no match", so
  `inode:filetype("Directory")` quietly means "not a directory". Use the exact
  seven names. Passing a third argument makes the call return nothing at all.
- **`inode:ids()` returns untranslated `kuid_t`/`kgid_t` values**, i.e. IDs as
  seen in the initial user namespace, with no idmap applied. Comparing them
  against a container's uid 0 is wrong. For ownership questions prefer
  `mntidmap:inode_owner_or_capable(inode)`.
- **`inode:ino()` is only unique within a filesystem.** Pair it with
  `superblock:magic()` or `superblock:fstype_name()` before using it in a
  decision.
- `inode:size()` is inherently racy: the size can change immediately after the
  read.
- **The argument order of `inode:xattr(dentry, name)` mirrors
  `dentry:xattr(inode, name)`** — the companion object is always second, so
  the pair you supply flips with the receiver. The same 128-byte cap,
  `nil, 34` (`ERANGE`) behaviour, missing pair-consistency check, and
  may-sleep restriction apply. Prefer `file:xattr(name)` when you hold a
  file.
- The kvcache dict lives in `inode->i_security`; when that blob is missing,
  reads return nothing and `kvcache_set` / `kvcache_incr` return
  `nil, "-ESRCH"`.
- Object validity is as described under `file`.
- No method memoizes; every call re-reads `struct inode`.

```lua
local errno = require("errno")

function M.inode_permission(inode, mask)
  if inode:filetype("chr") and inode:mode("woth") then
    return false, errno.EACCES
  end
  local uid = inode:ids()
  if uid == 0 and inode:mode(true, "suid", "xoth") then
    return false, errno.EPERM
  end
  return true
end
```

### `path`

A `path` wraps a *pointer to* a `struct path` — usually a caller stack
variable — and is handed to the `path_*` hooks, to `sb_mount`, and to
`inode_getattr`. It bundles a dentry with the mount it was reached through.

| Method | Arguments | Returns | On failure |
|---|---|---|---|
| `path:vfsmount()` | none | `vfsmount` | no failure path (no NULL check) |
| `path:dentry()` | none | `dentry` | no failure path (no NULL check) |
| `path1 == path2` | another `path` | `boolean` | `raises` only if you invoke the metamethod directly with a non-`path` |
| `path:type()` | none | `"path", false` | none |
| `tostring(path)` | none | `"path: '<dentry_path>'"` | a `"path: <err = ...>"` string whose error text is unreliable |

**Notes.**

- **Because a `path` object points at a caller stack variable, its validity
  window is the tightest of all**; see the validity note under `file`. Read
  what you need immediately.
- **`tostring(path)` ignores `path->mnt`.** It renders
  `dentry_path(path->dentry)`, so it shows the filesystem-relative path with
  no mount prefix and a `"//deleted"` marker for unlinked dentries
  (`security/lua/lua_fs.c:419-429`). No API in this module renders a
  `struct path` through `d_path`, so a `path` argument cannot be turned into a
  namespace-visible path; the only complete source for that is a `file`
  object. Do not rely on the error text of `tostring(path)` either — prefer
  `path:dentry():path()`, which reports `nil, errname` you can branch on.
- **`==` is pointer identity, not path equality.** It compares both the
  `dentry` and the `mnt` pointer, so two `path`s naming the same file through
  different bind mounts compare unequal, and two different `struct path`
  copies of the same location compare equal only if both pointers match. Lua
  invokes `__eq` only when both operands are `path` objects; comparing a
  `path` against a `dentry` or `file` yields `false` without any error.
- `path:vfsmount()` is the bridge to per-filesystem identity and to a
  long-lived kvcache dict: `path:vfsmount():superblock()`.
- A `path` has no kvcache dict.
- No method memoizes.

```lua
local errno = require("errno")

function M.path_mkdir(dir, dentry, mode)
  local sb = dir:vfsmount():superblock()
  if sb:fstype_name() ~= "tmpfs" then
    return true
  end
  if dir:dentry():path() == "/" then
    return false, errno.EPERM
  end
  return true
end
```

### `superblock`

A `superblock` wraps a `struct super_block *`. The `sb_*` hooks pass it, and
`vfsmount:superblock()` derives it. Superblocks are long-lived, which makes
their kvcache dict the best place to cache a per-filesystem verdict.

| Method | Arguments | Returns | On failure |
|---|---|---|---|
| `superblock:magic()` | none | `s_magic` as an integer | none |
| `superblock:root()` | none | `dentry` for the filesystem root | no failure path (no NULL check) |
| `superblock:fstype_name()` | none | filesystem type name, e.g. `"ext4"` | `nil` when `s_type` is NULL |
| `superblock:type()` | none | `"superblock", true` | none |
| `superblock:kvcache_get(key)` | `key`: string | stored value, or `nil` if unset | `nil` (no values at all) when there is no LSM blob |
| `superblock:kvcache_set(key, value)` | `key`: string; `value`: boolean, number, or light userdata (`nil` deletes the key) | `true` | `nil, errname`, or `nil, "unknown"` |
| `superblock:kvcache_incr(key [, delta])` | `key`: string; `delta`: number, default `1` | the new number | `nil, errname` |
| `tostring(superblock)` | none | `"superblock: '<fstype name>'"` | `"superblock: '<empty>'"` when `s_type` is NULL |

**Notes.**

- **`superblock:root()` has no NULL check** (`security/lua/lua_fs.c:449-454`).
  `s_root` is NULL in exactly the hooks that see a half-built superblock —
  `sb_alloc_security`, `sb_free_security`, and the mount-option hooks — so
  `superblock:root():path()` there dereferences NULL. There is no return value
  to test: guard by hook, and only call `root()` where the filesystem is fully
  set up. `fstype_name()` is the one accessor in this family that is
  explicitly NULL-guarded.
- **The type name string is a copy** of the kernel's static
  `file_system_type.name`, so unlike the objects themselves it is safe to keep
  across hooks — which makes it a good key for state you carry elsewhere.
- **No magic-number constants are exported.** Keep your own table of the
  values you care about (for example `0x01021994` for tmpfs) or match on
  `fstype_name()` instead.
- The dict lives in `sb->s_security` and is freed with the superblock. Values
  are still limited to booleans, numbers, and light userdata, so cache a
  verdict as a boolean rather than caching a name.
- Object validity is as described under `file`.
- No method memoizes.

```lua
local errno = require("errno")

function M.sb_mount(dev_name, path, type, flags, data)
  local sb = path:vfsmount():superblock()
  local trusted = sb:kvcache_get("trusted")
  if trusted == nil then
    trusted = sb:fstype_name() == "ext4"
    sb:kvcache_set("trusted", trusted)
  end
  if not trusted then
    return false, errno.EPERM
  end
  return true
end
```

### `binprm`

A `binprm` wraps a `struct linux_binprm *` and is handed to the `bprm_*`
hooks (`bprm_creds_for_exec`, `bprm_creds_from_file`, `bprm_check_security`,
`bprm_committing_creds`, `bprm_committed_creds`). Its four accessors are
pure field reads.

| Method | Arguments | Returns | On failure |
|---|---|---|---|
| `binprm:executable()` | none | `file` for the executable | `nil` when the field is NULL |
| `binprm:interpreter()` | none | `file` for the interpreter | `nil` when the field is NULL |
| `binprm:file()` | none | `file` currently being loaded | `nil` when the field is NULL |
| `binprm:cred()` | none | `cred` being prepared for the exec | `nil` when the field is NULL |
| `binprm:type()` | none | `"binprm", false` | none |
| `tostring(binprm)` | none | `"binprm: <0xffff...>"` | none |

**Notes.**

- **All four accessors can legitimately return `nil`**, so branch before
  calling a method on the result. `executable` is NULL until the binary format
  handler sets it, which means `bprm_creds_for_exec` normally sees `nil`; test
  in `bprm_check_security` instead. `interpreter` is non-NULL only for `#!`
  and `binfmt_misc` execution.
- **`binprm:file()` is not necessarily the binary the caller asked for**: after
  a `#!` chain it is the interpreter. Compare `executable()` and `file()` when
  the distinction matters.
- **`binprm:cred()` returns the *new*, pre-commit credentials**, not the
  caller's current ones. Read it to answer "is this exec gaining privileges";
  it is a live, writable kernel struct in the exec path, so treat any mutating
  helper on it with care.
- **`tostring(binprm)` prints a raw kernel pointer** — there is no `__tostring`
  override for this family — so do not log it from a production policy.
- A `binprm` has no kvcache dict; per-exec state belongs on the `file` you get
  from `binprm:file()`.
- Object validity is as described under `file`; none of the returned `file`
  or `cred` objects takes a reference.
- No method memoizes.

```lua
local errno = require("errno")

function M.bprm_check_security(bprm)
  local f = bprm:file()
  if not f then
    return true
  end
  local path = f:path()
  if path and string.sub(path, 1, 5) == "/tmp/" then
    return false, errno.EACCES
  end
  return true
end
```

### `vfsmount`

A `vfsmount` wraps a `struct vfsmount *`. It comes from `sb_umount` and the
mount-moving hooks, and from `path:vfsmount()`. Use it to get from a mount to
filesystem identity.

| Method | Arguments | Returns | On failure |
|---|---|---|---|
| `vfsmount:superblock()` | none | `superblock` | no failure path (no NULL check) |
| `vfsmount:mntidmap()` | none | `mntidmap` | no failure path; never `nil` |
| `vfsmount:type()` | none | `"vfsmount", false` | none |
| `tostring(vfsmount)` | none | `"vfsmount: <0xffff...>"` | none |

**Notes.**

- `vfsmount:superblock()` is unchecked, but `mnt_sb` is always set for a live
  mount, so this is the normal route to `magic()`, `fstype_name()`, and a
  durable kvcache dict.
- **`mntidmap()` never tells you whether a mount is idmapped.** A
  non-idmapped mount returns the `nop_mnt_idmap` sentinel, which is a valid
  non-NULL object, so a `nil` test proves nothing. Just pass the result to the
  ownership helpers; they behave correctly for both cases.
- **`tostring(vfsmount)` prints a raw kernel pointer**; there is no override.
- A `vfsmount` has no kvcache dict — put per-filesystem state on
  `vfsmount:superblock()`.
- Object validity is as described under `file`; the idmap is owned by the
  mount, so it dies with it.
- No method memoizes.

```lua
local errno = require("errno")

function M.sb_umount(mnt, flags)
  local sb = mnt:superblock()
  if sb:fstype_name() == "overlay" then
    return false, errno.EBUSY
  end
  return true
end
```

### `mntidmap`

A `mntidmap` wraps a `struct mnt_idmap *`. The `inode_*` hooks that carry an
idmap (for example `inode_setxattr`) pass one, and `vfsmount:mntidmap()`
derives one. Both methods are questions about the *acting task*: they
evaluate against `current`'s credentials, not against the inode alone.

| Method | Arguments | Returns | On failure |
|---|---|---|---|
| `mntidmap:inode_owner_or_capable(inode)` | `inode`: an `inode` object, mandatory | `boolean` | `raises` on a missing or wrong-typed `inode` |
| `mntidmap:capable_wrt_inode_uidgid(inode, cap)` | `inode`: an `inode` object; `cap`: capability **number** | `boolean` | `raises` on a wrong-typed `inode` or a non-numeric `cap` |
| `mntidmap:type()` | none | `"mntidmap", false` | none |
| `tostring(mntidmap)` | none | `"mntidmap: <0xffff...>"` | none |

**Notes.**

- **`inode_owner_or_capable()` is the idmap-correct way to ask "does the
  caller own this file"** — it maps `current`'s fsuid through the mount idmap
  and falls back to `CAP_FOWNER` in the inode's user namespace. Prefer it over
  comparing `inode:ids()` yourself, which ignores idmapping entirely.
- **Both methods can emit an audit record** for the capability fallback; no
  no-audit option is exposed. Calling them on a hot path floods the audit log,
  so gate them behind a cheaper check.
- **`cap` must be a number.** Unlike the capability helpers elsewhere in this
  LSM, this method does not accept `"sys_admin"`-style names — a string
  raises. Take the value from the `capability` library. There is also no
  range validation, so an out-of-range number is passed straight through to
  the kernel.
- Both methods return a plain boolean and never an errno.
- A `mntidmap` has no kvcache dict.
- Object validity is as described under `file`.
- No method memoizes.

```lua
local errno = require("errno")

function M.inode_setxattr(idmap, dentry, name, value, flags)
  if name ~= "security.mylabel" then
    return true
  end
  local inode = dentry:backing_inode()
  if not inode or not idmap:inode_owner_or_capable(inode) then
    return false, errno.EPERM
  end
  return true
end
```

### `fscontext`

An `fscontext` wraps a `struct fs_context *` and is handed to the
`fs_context_*` hooks (`fs_context_submount`, `fs_context_dup`,
`fs_context_parse_param`, `fs_context_parse_monolithic`). Its single method is
the only mutating operation in the whole `fs` library.

| Method | Arguments | Returns | On failure |
|---|---|---|---|
| `fscontext:parse_fs_string(key, value)` | `key`: option name; `value`: option value, mandatory | `boolean` — `true` when the parser accepted the option | `false` with the errno discarded; `raises` if `key` or `value` is not a string or number |
| `fscontext:type()` | none | `"fscontext", false` | none |
| `tostring(fscontext)` | none | `"fscontext: <0xffff...>"` | none |

**Notes.**

- **This call changes the mount being constructed.** It feeds the option to
  the filesystem's parameter parser, so a policy can inject `nosuid`, `nodev`,
  or an fs-specific option into a mount in progress. Use it only from a hook
  that owns a live `fs_context`.
- **The errno is thrown away**, so a `false` return cannot distinguish
  "unknown option" from `-ENOMEM`. Treat `false` as "the mount cannot be
  constrained as required" and deny.
- **`value` is mandatory.** You cannot pass `nil` to mean "a flag with no
  value", even though the underlying kernel helper accepts NULL. The value is
  wrapped as a NUL-terminated string, so an embedded NUL truncates it and a
  binary value is impossible.
- It sleeps and allocates, and the filesystem parser may re-enter LSM hooks;
  do not call it from atomic or RCU context.
- **`tostring(fscontext)` prints a raw kernel pointer**; there is no override.
- An `fscontext` has no kvcache dict.
- Object validity is as described under `file`.

```lua
local errno = require("errno")

function M.fs_context_parse_param(fc, param)
  if not fc:parse_fs_string("mode", "0700") then
    return false, errno.EINVAL
  end
  return true
end
```


### `sock`

`sock` wraps a `struct sock *`, the protocol-independent half of a kernel
socket. You receive one from the sock-level hooks — `socket_sock_rcv_skb`,
`netlink_send`, `sk_alloc_security`, `sk_clone_security`, `sock_graft`,
`inet_conn_request`, `inet_conn_established`, `sctp_bind_connect`,
`mptcp_add_subflow`, `unix_stream_connect` — and from `socket:sock()`,
`skb:sock()` and `skb:full_sk()`. It is the only net object that carries a
per-module key/value cache.

| Method | Arguments | Returns | On failure |
|---|---|---|---|
| `sock:socket()` | none | 1: `socket` | `nil` when `sk->sk_socket` is NULL |
| `sock:suites([family [, type [, proto]]])` | up to 3 selectors, truthiness only, any type accepted | 0 to 3 strings, always in the order family, type, protocol | `"unknown"` for a field this build does not name |
| `sock:proto()` | none | 1: number, the raw `sk_protocol` value | never `nil` |
| `sock:listener([time_wait])` | 1 optional selector, truthiness only | 1: boolean | never `nil` |
| `sock:is_inet()` | none | 1: boolean | never `nil` |
| `sock:is_tcp()` | none | 1: boolean | never `nil` |
| `sock:is_udp()` | none | 1: boolean | never `nil` |
| `sock:is_stream_unix()` | none | 1: boolean | never `nil` |
| `sock:is_vsock()` | none | 1: boolean | never `nil` |
| `sock.key` | string key (via `__index`) | 1: the stored boolean, number or lightuserdata | `nil` |
| `sock.key = v` | string key, value (`nil` deletes) | 1: `true` | `nil, errno` |
| `sock:kvcache_get(key)` | string key | 1: stored value | `nil` |
| `sock:kvcache_set(key, v)` | string key, value (`nil` deletes) | 1: `true` | `nil, errno` |
| `sock:kvcache_incr(key [, n])` | string key, optional number, default `1` | 1: number, the new total | `nil, errno` |
| `sock:type()` | none | 2: `"sock"`, `true` | raises |
| `tostring(sock)` | none | 1: string, `sock: <ffff...>` | raises |

**Notes.**

- Every method raises if `self` is not a `sock` — the type check walks the
  userdata's metatable chain and calls `luaL_typerror` on a mismatch
  (`security/lua/auxlib.c:381`). A wrong-type `self` is never a `nil` return.
- `sock:suites()` uses its arguments as *selectors*, and a suppressed value
  is omitted from the result list rather than returned as `nil`, so later
  values shift left (`security/lua/lua_net.c:94`). The selector block runs
  only when at least one argument follows `self`:

  | Call | Values returned |
  |---|---|
  | `sk:suites()` | 3: family, type, protocol |
  | `sk:suites(true)` | 1: family |
  | `sk:suites(true, true)` | 2: family, type |
  | `sk:suites(true, true, true)` | 3: family, type, protocol |
  | `sk:suites(true, false, true)` | 2: family, protocol |
  | `sk:suites(false, true)` | 1: type |
  | `sk:suites(false, true, true)` | 2: type, protocol |
  | `sk:suites(false, false, true)` | 1: protocol |
  | `sk:suites(false)`, `sk:suites(nil)` | 0: nothing |

  With no argument after `self` you get all three; otherwise the count equals
  the number of truthy selectors. Selectors go through `lua_toboolean`, so
  `0` and `""` are truthy and nothing raises. Either take all three values or
  pass a selector for each value you name, and never mix the two:

  ```lua
  function M.netlink_send(sk, skb)
    local family, stype, proto = sk:suites()   -- 3 names, 3 values
    local proto_only = sk:suites(false, false, true)
    -- wrong: proto is nil and stype holds the protocol
    -- local family, stype, proto = sk:suites(false, true, true)
    return true
  end
  ```

- Family strings are `"unspec"`, `"inet"`, `"inet6"`, `"unix"`, `"netlink"`,
  `"packet"`, `"key"`, `"appletalk"`, `"alg"`, `"nfc"`, `"vsock"`, `"kcm"`,
  `"smc"`. Type strings are `"stream"`, `"dgram"`, `"raw"`, `"rdm"`,
  `"seqpacket"`, `"dccp"`, `"packet"`. Protocol strings are `"ip"`, `"icmp"`,
  `"igmp"`, `"tcp"`, `"egp"`, `"udp"`, `"dccp"`, `"ipv6"`, `"esp"`, `"l2tp"`,
  `"sctp"`, `"udplite"`, `"raw"`, `"smc"`, `"mptcp"`. Anything else in a slot
  becomes `"unknown"`. `"raw"`, `"dccp"` and `"packet"` appear in two
  namespaces, so compare the type and protocol results separately.
- `sock:proto()` reads `sk_protocol` without an `sk_fullsock()` guard, so on
  output-path and connection-setup hooks, where `skb:sock()` can hand you a
  request or time-wait mini-sock, the number is garbage. Reach the socket
  through `skb:full_sk()` whenever you intend to read protocol fields, or
  gate on `sock:listener(true)` first.
- Prefer `sock:is_tcp()` and friends over string matching: they come from the
  kernel `sk_is_*()` helpers, which check family, type and protocol together.
- `sock:listener(true)` matches listening sockets, request socks and
  TIME_WAIT socks; `sock:listener()` matches listening and request socks
  only.
- Keys written through `sock.key`, `sock:kvcache_set()` and
  `sock:kvcache_incr()` live in a per-policy-module namespace attached to the
  sock's LSM blob, so two policies never see each other's keys. Only
  booleans, numbers and lightuserdata are storable; a string or table value
  fails with `nil, "-EINVAL"`.
- Reads through `sock.key` walk the metatable chain first, so a key that
  collides with a method name — `type`, `proto`, `suites`, `listener`,
  `socket` — returns the method instead of your value. Do not use a method
  name as a label key, and use `sock:kvcache_get(key)` when the key comes
  from data.
- The second value of a failed kvcache call is an error *name* string with a
  leading minus, such as `"-ENOMEM"` or `"-EINVAL"`, falling back to the literal
  `"unknown"`; the store formats the negative errno it already holds
  (`security/lua/kvcache.c:129`). It is not a number, so do not hand it back
  as a hook errno.
- No method takes a lock or enters an RCU read-side critical section; each
  one is a plain unlocked load from the live kernel struct.

### `skb`

`skb` wraps a `struct sk_buff *`, one packet in flight. The skb-carrying
hooks are `socket_sock_rcv_skb(sk, skb)`, `netlink_send(sk, skb)`,
`inet_conn_request(sk, skb, req)`, `inet_conn_established(sk, skb)`,
`socket_getpeersec_dgram(sock, skb, secid)`, `sctp_assoc_request`,
`sctp_assoc_established` and `xfrm_decode_session(skb, ...)`. It has no
key/value cache, so you cannot attach per-packet state.

| Method | Arguments | Returns | On failure |
|---|---|---|---|
| `skb:sock()` | none | 1: `sock` | `nil` when `skb->sk` is NULL |
| `skb:full_sk()` | none | 1: `sock` | `nil` when there is no full socket |
| `skb:protocol()` | none | 1: string, one of `"loop"`, `"ip"`, `"ipv6"`, `"arp"`, `"rarp"` | `"unknown"` |
| `skb:iif()` | none | 1: number, the receiving `ifindex` | never `nil`; `0` when unset |
| `skb:secmark()` | none | 1: number, `skb->secmark` | never `nil`; `0` when unmarked |
| `skb:len()` | none | 1: number, `skb->len` | never `nil` |
| `skb:read(off, len)` | 2 required integers | 1: binary-safe string of exactly `len` bytes | `nil` |
| `skb:type()` | none | 2: `"skb"`, `false` | raises |
| `tostring(skb)` | none | 1: string, `skb: <ffff...>` | raises |

**Notes.**

- **A `skb` is valid only inside the hook that produced it.** All four net
  objects hold a bare kernel pointer with no reference count, no generation
  counter and no `__gc`, and nothing revalidates them. If you stash an `skb`
  in a module-level table or in `shared` and call `skb:read()` from a later
  hook, you read freed memory. Extract what you need — bytes, lengths,
  addresses — while you are still inside the hook, and store only those
  plain Lua values.
- `off` is measured in bytes from `skb->data`, the hook's *current* data
  pointer. That pointer sits at a different protocol layer depending on
  which hook you are in, so you must know your hook before you compute an
  offset: on `netlink_send` the data starts at the netlink message, on the
  receive-path hooks it starts wherever the calling protocol code left it.
  Offset `0` is not "the Ethernet header" and not `skb->head`. Confirm the
  layer for the specific hook you register, then hard-code offsets relative
  to it.
- `len` is capped at `SKB_READ_MAX`, currently 256
  (`security/lua/lua_net.c:26`); the destination is a 256-byte on-stack
  buffer. To read more, loop with increasing offsets.
- Out-of-range arguments return `nil` with no reason: `len < 0`, `len > 256`,
  `off < 0`, `off > skb:len()`, or `len > skb:len() - off`. A missing or
  non-numeric argument **raises** instead, because both go through
  `luaL_checkinteger` (`security/lua/lua_net.c:355`) — so `skb:read()` and
  `skb:read(0, "4")` are Lua errors, not `nil`. A valid `skb:read(off, 0)`
  returns `""`, which is truthy, so test for `nil` explicitly rather than
  testing truthiness of the result.
- `skb:len()` is `skb->len`: the number of readable bytes from `skb->data`
  onward, linear plus paged. It usually still includes protocol headers and
  is not a payload length. It is exactly the bound `skb:read()` enforces, and
  the copy goes through `skb_copy_bits()`, so fragmented data is handled for
  you.
- Bytes come out in wire order and there is no `bit` library, so decode
  multi-byte fields with `string.byte` and arithmetic:

  ```lua
  local errno = require("errno")

  local DPORT_OFF = 2 -- offset of the TCP destination port for this hook

  function M.socket_sock_rcv_skb(sk, skb)
    local raw = skb:read(DPORT_OFF, 2)
    if raw == nil then return true end
    local hi, lo = string.byte(raw, 1, 2)
    if hi * 256 + lo == 22 then return false, errno.EACCES end
    return true
  end
  ```

- `skb->protocol` is often 0 on locally generated egress packets, so
  `"unknown"` from `skb:protocol()` does not imply an exotic protocol.
- `skb:secmark()` is meaningful only on kernels built with
  `CONFIG_NETWORK_SECMARK`, and it is read-only — there is no setter.
- `skb:sock()` can hand you a request or time-wait mini-sock; use
  `skb:full_sk()` before reading full-socket fields such as `sock:proto()`.

### `socket`

`socket` wraps a `struct socket *`, the VFS-facing half of a socket. Nearly
every `socket_*` hook passes one — `socket_post_create`, `socket_bind`,
`socket_connect`, `socket_listen`, `socket_accept`, `socket_shutdown`,
`socket_getsockopt`, `socket_setsockopt`, `socket_getsockname`,
`socket_getpeername`, `socket_socketpair`, `unix_may_send`, `sock_graft` —
and `net.sock_alloc()` returns a fresh one.

| Method | Arguments | Returns | On failure |
|---|---|---|---|
| `socket:release()` | none | 0 values | never fails; a second call is a no-op |
| `socket:sock()` | none | 1: `sock` | `nil` when `sock->sk` is NULL |
| `socket:inode()` | none | 1: `inode` | never `nil` |
| `socket:type()` | none | 2: `"socket"`, `false` | raises |
| `tostring(socket)` | none | 1: string, `socket: <ffff...>` | raises |

**Notes.**

- Do not call `release()` on a socket a hook handed you. It calls the kernel
  `sock_release()` unconditionally and then NULLs the userdata slot
  (`security/lua/lua_net.c:236`), and nothing distinguishes a socket you
  allocated from a live kernel-owned one reached through `sock:socket()` or a
  hook argument — so the call destroys a running process's socket from inside
  your policy. Reserve `release()` for the exact `socket` value that
  `net.sock_alloc()` returned to you, in the same hook.
- After `release()` the userdata is still a valid Lua `socket` holding NULL.
  `socket:sock()` dereferences it and `socket:inode()` does `container_of()`
  pointer arithmetic on it, so both fault in the kernel instead of raising a
  Lua error. Drop the variable immediately after releasing.
- `socket:inode()` never returns `nil` — there is no NULL check — so the
  result is only trustworthy for a socket that is still live.
- The returned `inode` is a full `fs` object with its own method set and its
  own key/value cache; see the `inode` section.
- Like `sock` and `skb`, a `socket` is valid only for the duration of the
  hook that produced it.

### `sockaddr`

`sockaddr` wraps a `struct sockaddr *`, the address a caller supplied. It
reaches you from `socket_bind(sock, sa)`, `socket_connect(sock, sa)` and
`sctp_bind_connect(sk, optname, sa)`.

| Method | Arguments | Returns | On failure |
|---|---|---|---|
| `sockaddr:family()` | none | 1: string, same vocabulary as `sock:suites()` family | `"unknown"` |
| `sockaddr:addrs([readable])` | 1 optional selector, truthiness only | 3 for `AF_INET`/`AF_INET6`: family, address, port; 2 for `AF_UNIX`: family, `sun_path` | 0 values for every other family |
| `tostring(sa)` | none | 1: string, `sa.<family>: <address>` | never fails |
| `sockaddr:type()` | none | 2: `"sockaddr"`, `false` | raises |

**Notes.**

- The address argument is only pushed when `addrlen` covers the family's
  minimum size (`security/lua/lsm_defs.c:2720`). A truncated address means
  the hook is called with that parameter absent, so treat a `nil` `sa` as
  "no address" rather than assuming an object is always there.
- `addrs()` returns different Lua *types* per family, so branch on the first
  return value before you touch the second. For `AF_INET` the non-readable
  address is a **number**, the raw `sin_addr.s_addr` in network byte order.
  For `AF_INET6` it is a **16-byte binary string** of `sin6_addr`. For
  `AF_UNIX` there is no third value. For netlink, packet, vsock and anything
  else you get **zero values**, so `local fam = sa:addrs()` leaves `fam` as
  `nil`.

  ```lua
  local net = require("net")
  local errno = require("errno")

  function M.socket_connect(sock, sa)
    local family, addr, port = sa:addrs()
    if family == "inet" and addr == net.in4_pton("10.0.0.1") then
      return false, errno.EACCES
    end
    if family == "inet6" and addr == net.in6_pton("2001:db8::1") then
      return false, errno.EACCES
    end
    return true
  end
  ```

- Compare the non-readable forms against `net.in4_pton()` (number, network
  order) and `net.in6_pton()` (16-byte string) respectively; run an IPv4
  value through `net.ntohl()` before doing arithmetic on it.
- `addrs(true)` gives a printable address that **excludes** the port —
  `"10.0.0.1"`, `"2001:db8::1"` — because the kernel format is `%pISc`. The
  port always comes back separately as the third value. `tostring(sa)` uses
  `%pISpc` and therefore **includes** it: `sa.inet: 10.0.0.1:80`,
  `sa.inet6: [2001:db8::1]:80`. Use `addrs(true)` when you match on the
  address alone and `tostring(sa)` for log lines.
- The port from `addrs()` is already host order, converted with `ntohs()`;
  do not swap it again.
- An abstract `AF_UNIX` address has `sun_path[0] == '\0'`, so `addrs()`
  flattens it to `""` and the abstract name is lost; unnamed and autobind
  sockets also give `""`. There is no `addrlen` exposed to tell them apart.
- `sin6_flowinfo` and `sin6_scope_id` are never exposed. A netlink `nl_pid`
  appears only as text inside `tostring(sa)`.
- A `sockaddr` points at caller-supplied kernel memory and is valid only
  inside the hook that produced it.
