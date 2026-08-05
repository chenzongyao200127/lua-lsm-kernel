# Lua-LSM Library Reference

The seven built-in libraries. See `API.md` for the module format and calling conventions, `OBJECTS.md` for object types, and `HOOKS.md` for the hook table.


Seven libraries are built in: `kernel`, `fs`, `net`, `errno`, `capability`,
`signal`, and `audit` (`security/lua/lsm.c:800`). None of them is a global, so
each one you use needs an explicit `require()` at the top of your chunk:

```lua
local errno = require("errno")
local capability = require("capability")
```

`require()` on an unknown name returns `nil` rather than raising, so a
misspelled library name shows up later as "attempt to index a nil value".

### `kernel`

The `kernel` library exposes kernel-wide facts and primitives that are not tied
to any one object: the kernel version, the runtime hook list, a random number
source, a coarse clock, RCU bracketing, pid lookup, and the printk levels. It is
a plain library, so a policy must `require('kernel')`; it is not a global. The
table contains functions only — no constants.

| Method | Arguments | Returns | On failure |
|---|---|---|---|
| `kernel.version()` | none | 3 integers in order: major, patchlevel, sublevel | cannot fail |
| `kernel.lsm_funcs()` | none | 1 table: array of `{ name, rettype, c_nargs }` triples | cannot fail |
| `kernel.random()` | none | 1 integer, uniform over `[0, 4294967295]` | cannot fail |
| `kernel.random(hi)` | `hi`: integer, `>= 0` | 1 integer in `[1, hi]` | raises `"interval is empty"` when `hi < 0` |
| `kernel.random(lo, hi)` | `lo`, `hi`: integers, `0 <= lo <= hi` | 1 integer in `[lo, hi]` inclusive | raises `"interval is empty"` when `lo > hi`; raises `"wrong number of arguments"` beyond two arguments |
| `kernel.ktime_seconds([monotonic])` | `monotonic`: any truthy value selects the monotonic clock | 1 integer: whole seconds | cannot fail |
| `kernel.rcu_read_lock()` | none | no values | cannot fail |
| `kernel.rcu_read_unlock()` | none | no values | cannot fail |
| `kernel.task_from_pid(pid)` | `pid`: integer, interpreted as a vpid | 1 `task` holding its own reference | `nil` when no such task exists; raises on a non-number |
| `kernel.printk(msg)` | `msg`: string or number | no values | raises on any other type |
| `kernel.pr_emerg(msg)`, `pr_alert`, `pr_crit`, `pr_err`, `pr_warn`, `pr_notice`, `pr_info`, `pr_cont`, `pr_devel`, `pr_debug` | `msg`: string or number | no values | raises on any other type |

**Notes.**

- `kernel.version()` reports compile-time constants of the kernel the LSM was
  built into, not a runtime query. It tells you what the module was compiled
  against and nothing about what is running elsewhere.
- `kernel.lsm_funcs()` is the authoritative list of hook names this kernel will
  dispatch to your policy. It is filtered by the running kernel's config —
  `getprocattr`, `setprocattr`, `lsmprop_to_secctx` and the key, perf, tun,
  infiniband and xfrm groups are excluded — so consult it at runtime instead of
  hardcoding a list. Element `[2]` is the stringified C return type (`"int"`,
  `"void"`); a `"void"` hook cannot deny anything, whatever your function
  returns. Element `[3]` is `COUNT_ARGS()` over the hook's **C** prototype
  (`security/lua/lua_kernel.c:530`), so it is not the number of arguments your
  Lua function receives; see
  [Lua arity is not C arity](API.md#lua-arity-is-not-c-arity).

  ```lua
  local kernel = require('kernel')

  for _, h in ipairs(kernel.lsm_funcs()) do
    if h[1] == 'file_mprotect' then
      kernel.pr_info('file_mprotect available, ' .. h[3] .. ' C args')
    end
  end
  ```

- **`kernel.random(lo, hi)` supports non-negative bounds only.** The one-argument
  form rejects a negative bound outright, but the two-argument form checks only
  `lo <= hi` and then converts both bounds to unsigned 32-bit values. A negative
  `lo` therefore becomes a huge unsigned number, inverting the interval and
  producing a kernel warning plus a garbage result. Stay within
  `0 <= lo <= hi <= 4294967295`, and shift into a signed range yourself if you
  need negative output. `kernel.random(0)` returns `1`.
- **Units.** `kernel.ktime_seconds()` returns whole seconds, never
  sub-second and never jiffies or nanoseconds. There is no higher-resolution
  clock in this API, so rate limiting built on it has one-second granularity.
  Without an argument it reads CLOCK_REALTIME — seconds since the Unix epoch,
  which jumps with `settimeofday` and NTP steps. With any truthy argument it
  reads CLOCK_MONOTONIC — seconds since boot, excluding suspended time. Use the
  monotonic form for anything that measures elapsed time, and the realtime form
  only for log timestamps.

  ```lua
  local kernel = require('kernel')
  local errno = require('errno')

  function M.file_mprotect(vma, reqprot, prot)
    local st = shared.wxstate          -- named shared dict
    local now = kernel.ktime_seconds(true)   -- monotonic seconds
    if vma:wx() and now - (st.last or 0) < 60 then
      return false, errno.EACCES
    end
    st.last = now
    return true
  end
  ```

- **Namespaces.** `kernel.task_from_pid()` resolves the pid with
  `find_get_task_by_vpid()`, so the number is interpreted in the pid namespace of
  `current` — not the initial namespace. It also matches thread ids, not only
  thread group leaders. The returned `task` owns a reference and stays
  dereferenceable after the hook returns, which makes it the one `task` you may
  keep; validate it with `task:pid_alive()` before use. Note the asymmetry with
  `task:pids()`, which reports initial-namespace ids.
- `kernel.rcu_read_lock()` and `kernel.rcu_read_unlock()` are raw, unbalanced
  primitives. Nothing tracks nesting, and any Lua error raised between them —
  including one raised by an argument check inside the protected block — unwinds
  past the unlock and leaves the CPU in an RCU read-side section. While the lock
  is held you must not sleep, so `task:cmdline()` is forbidden, and allocations
  downgrade to `GFP_ATOMIC`, making path and cmdline lookups fail more often.
  Prefer not to use these at all; if you must, wrap the protected region in
  `pcall`.
- The ten `pr_*` functions differ only in printk level; `kernel.printk()` is an
  alias for the `pr_info` level. All eleven take exactly one string, append a
  newline, and return nothing. Messages are truncated at the first embedded NUL
  and at printk's per-record limit of roughly one kilobyte. `pr_cont` still
  appends a newline, so it does not continue a line. `pr_devel` and `pr_debug`
  compile to nothing unless debugging is enabled for the file, so treat those two
  as discardable.
- There is no rate limiting on any of these, so a print in a hot hook floods
  `dmesg`. Paths, `comm` and `cmdline` are attacker-influenced strings; logging
  them raw is a log-injection surface. Prefer `audit.log` for anything a tool
  will parse.

### `audit`

The `audit` library emits a structured kernel audit record from a policy. It
holds one function and no constants, and a policy must `require('audit')`.

| Method | Arguments | Returns | On failure |
|---|---|---|---|
| `audit.log(fields)` | `fields`: table with string keys matching `[A-Za-z_][A-Za-z0-9_]*` and string, number or boolean values | 1 boolean: `true` when a record was emitted | `false` when kernel audit is disabled or the audit buffer cannot be allocated; raises on a non-table argument or an invalid key or value |

**Notes.**

- The record is type `AUDIT_LUA` (1427) and is attached to the current syscall's
  audit context, so `ausearch` correlates it with the SYSCALL record. The first
  field is always `lmod=<module>`, the chunk name the policy module was loaded
  under. A user field literally named `lmod` is accepted and produces a duplicate
  field in one record, which confuses `ausearch` and `aureport` — do not use that
  key.
- **`audit.log` validates its arguments only when kernel audit is enabled.** The
  `audit_enabled` test runs before the argument is even type-checked
  (`security/lua/lua_audit.c:85`), so on a machine with auditing off,
  `audit.log(42)` and `audit.log{ ['2bad'] = 1 }` both return `false` in silence.
  Turn auditing on the moment those calls start raising. Develop and test every
  policy with auditing enabled, and do not rely on a passing run with auditing
  off to mean your `audit.log` calls are well-formed.
- Keys must be non-empty, must not start with a digit, and may contain only
  letters, digits and underscore; a leading underscore is allowed. A plain list
  such as `{ 'a', 'b' }` is rejected, because its keys are numbers. Values must
  be strings, numbers or booleans — a table, userdata or function raises.
  Validation covers the whole table before anything is written, so a rejected
  call never leaves a partial record behind.
- Booleans are written as `1` and `0`. Numbers go through a signed 64-bit
  conversion and print as signed decimal, so an address above `2^63` prints
  negative and a bitmask cannot exceed `2^63 - 1`. Strings keep embedded NULs and
  non-printable content is hex-encoded by the audit layer.
- Field order after `lmod` follows Lua hash iteration order, which is
  unspecified and may vary between runs. Never write a parser that depends on
  ordering; match on `key=` instead.
- The record buffer is allocated with the same flags as the rest of this API, so
  the call works in atomic context but fails more often there, and `false` also
  means "audit backlog limit reached". Treat `false` as "not recorded" and make
  the enforcement decision independently — never gate a deny on a successful
  log.

  ```lua
  local audit = require('audit')
  local capability = require('capability')
  local errno = require('errno')

  function M.userns_create(cred)
    if cred:capable(capability.CAP_SYS_ADMIN) then
      return true
    end
    local uid = cred:uids()
    audit.log{ op = 'userns_create', uid = uid, denied = true }
    return false, errno.EPERM
  end
  ```

### `fs`

The `fs` library is not a global: load it with `local fs = require("fs")`.
The table holds exactly one function; everything else in this section reaches
you as a hook argument.

| Method | Arguments | Returns | On failure |
|---|---|---|---|
| `fs.filp_open(filename, flags, mode)` | `filename`: string; `flags`: raw `O_*` bits as a number; `mode`: number narrowed to 16 bits | a GC-managed `file` object | `nil, errno` where the errno is **negative** (`-2` for `ENOENT`); `raises` if any of the three arguments is missing or not a string/number |

**Notes.**

- **The returned `file` is the one object with a managed lifetime.** It owns
  an `fput` reference released by `file:fput()` or, eventually, by garbage
  collection. Prefer calling `fput()` explicitly, since in-kernel Lua
  collection is not prompt and the reference pins the file until then.
  `fput()` raises on any other file object, and it is idempotent on this one.
- **The failure convention differs from everything else in this library.**
  `fs.filp_open` yields a *negative* errno integer, `file:xattr()` yields a
  *positive* one, and the path renderers yield an errno *name* string such as
  `"-ENAMETOOLONG"`. Do not funnel them through one shared error handler.
- **No `O_*` constants are exported here.** Pass literals (`0` is
  `O_RDONLY`) or take the values from another library.
- **This call sleeps, allocates, resolves the path against `current`'s root
  and mount namespace, and re-enters the LSM hook machinery**, so an
  `fs.filp_open` inside a file hook can recurse into your own policy. Use it
  only from sleepable hooks, and only where you can afford the re-entrancy.
- `mode` above `0xFFFF` is silently truncated, and an embedded NUL truncates
  `filename`.

```lua
local fs = require("fs")
local errno = require("errno")

function M.bprm_check_security(bprm)
  local f, err = fs.filp_open("/etc/policy.stamp", 0, 0)
  if not f then
    return false, errno.EACCES
  end
  local empty = f:size() == 0
  f:fput()
  if empty then
    return false, errno.EPERM
  end
  return true
end
```

### `net`

`net` holds the address-conversion helpers and the one socket constructor.
Load it with `local net = require("net")`; it is preloaded but not a global.
The object types it hands out — `sock`, `socket`, `skb`, `sockaddr` — are
documented under Object reference.

| Method | Arguments | Returns | On failure |
|---|---|---|---|
| `net.sock_alloc()` | none | 1: `socket` | 0 values, which reads as `nil` |
| `net.htonl(n)` | 1 integer | 1: number, truncated to 32 bits | raises |
| `net.ntohl(n)` | 1 integer | 1: number, truncated to 32 bits | raises |
| `net.htons(n)` | 1 integer | 1: number, truncated to 16 bits | raises |
| `net.ntohs(n)` | 1 integer | 1: number, truncated to 16 bits | raises |
| `net.in_aton(s)` | 1 string | 1: number, `__be32` in network order | never fails |
| `net.in4_pton(s)` | 1 string | 1: number, `__be32` in network order | `nil` |
| `net.in6_pton(s)` | 1 string | 1: 16-byte binary string | `nil` |

**Notes.**

- All four byte-order helpers use `luaL_checkinteger`, so a non-numeric
  argument raises rather than returning `nil`. The result is widened from an
  unsigned type and is always non-negative, and the input is silently
  truncated to 32 or 16 bits.
- `net.in_aton()` has no way to report a parse error: it consumes what it can
  and returns a value regardless, so `net.in_aton("hello")` yields a garbage
  address. Use `net.in4_pton()` for anything derived from data, and check for
  `nil`.
- `net.in4_pton()` returns a number and `net.in6_pton()` returns a 16-byte
  binary string. These are exactly the representations that
  `sockaddr:addrs()` produces without its `readable` selector, so binary
  comparison works in both families:

  ```lua
  local net = require("net")
  local errno = require("errno")

  function M.socket_bind(sock, sa)
    local family, addr = sa:addrs()
    if family == "inet" and addr == net.in4_pton("0.0.0.0") then
      return false, errno.EACCES
    end
    return true
  end
  ```

- Both `pton` helpers stop at a `'\n'` delimiter and take the string length
  from Lua, so embedded NULs are safe.
- `net.sock_alloc()` returns nothing on allocation failure, so a plain
  `local s = net.sock_alloc()` gives `nil`; test for it. Nothing registers a
  `__gc` for `socket`, so the allocated `struct socket` and its inode leak
  unless you call `socket:release()` on that value before the hook returns.
  Policies rarely need this function at all.

### `capability`

`capability` exposes the kernel capability constants, a capability-bit test
against the current task's credentials, and the `cap` set object. Load it
with `local capability = require("capability")`. It is the library behind the
`capable` hook's `cap` argument.

| Method | Arguments | Returns | On failure |
|---|---|---|---|
| `capability.cap_empty()` | none | 1: `cap` holding `CAP_EMPTY_SET` | never fails |
| `capability.cap_full()` | none | 1: `cap` holding `CAP_FULL_SET` | never fails |
| `capability.capable(cap)` | 1 capability, number or string | 1: boolean | raises on an out-of-range number or a non-number, non-string; an unmatched string silently becomes `CAP_CHOWN` |
| `capability.capable(userns, cap [, opt...])` | `userns` object, capability, optional `"noaudit"` / `"insetid"` strings | 1: boolean | raises |
| `cap:type()` | none | 2: `"cap"`, `false` | raises |
| `tostring(cap)` | none | 1: string, `cap: <ffff...>` | raises |

Set arithmetic on `cap` objects is exposed only as operators; there are no
named methods and no way to test or list a single bit of a `cap`.

| Operator | Arguments | Returns | On failure |
|---|---|---|---|
| `cap1 + cap2` | two `cap` objects | 1: new `cap`, the union | raises |
| `cap1 + name` | `cap`, capability number or string | 1: new `cap` with that bit raised | raises |
| `cap1 - cap2` | two `cap` objects | 1: new `cap`, the difference | raises |
| `cap1 - name` | `cap`, capability number or string | 1: new `cap` with that bit lowered | raises |
| `cap1 * cap2` | two `cap` objects | 1: new `cap`, the intersection | raises |
| `cap1 == cap2` | two `cap` objects | 1: boolean, identical sets | raises |
| `cap1 <= cap2` | two `cap` objects | 1: boolean, `cap1` is a subset | raises |
| `cap1 < cap2` | two `cap` objects | 1: boolean, proper subset | raises |

**Notes.**

- The constants are generated at library-open time, not hand-listed in Lua:
  `setconst()` walks a `CONST_DEFINE(name)` table and assigns
  `capability[name] = value` as a Lua number
  (`security/lua/auxlib.c:404`). The values come from
  `<linux/capability.h>` in the building kernel, and the names are the exact
  kernel spellings, upper-case with the `CAP_` prefix:
  `capability.CAP_SYS_ADMIN`, `capability.CAP_NET_ADMIN`,
  `capability.CAP_NET_RAW`, `capability.CAP_DAC_OVERRIDE`,
  `capability.CAP_BPF`.
- The table covers `CAP_CHOWN` through `CAP_CHECKPOINT_RESTORE`. A newer
  capability the running kernel supports is simply absent and reads as `nil`,
  and passing that `nil` to `capable()` raises. There is no `CAP_LAST_CAP`.
- Enumerate the real set at load time rather than trusting a written list.
  Functions share the table with the constants, so filter on the value type:

  ```lua
  local capability = require("capability")
  local kernel = require("kernel")

  for name, value in pairs(capability) do
    if type(value) == "number" then
      kernel.pr_info(name .. " = " .. value)
    end
  end
  ```

- Anywhere a capability is expected you may pass the number or a lower-case
  string without the `CAP_` prefix — `"sys_admin"`, `"net_raw"`,
  `"dac_override"` — matched against its own table
  (`security/lua/auxlib.c:491`). An unmatched **string** does not raise: the
  lookup leaves the value at `0`, and `0` is a valid capability — `CAP_CHOWN` —
  so a misspelled name silently tests the wrong bit. Only an out-of-range
  number, or an argument that is neither a number nor a string, raises
  `luaL_argerror`. Pass the constants.
- `capability.capable()` always tests the **current** task's credentials with
  `cap_capable()`; the optional first argument only selects the user
  namespace to test against. It is a pure capability-bit test, not the full
  `security_capable()` stack, and it does not emit an audit record of its
  own.
- Call it with a capability alone, or with a `userns` object followed by a
  capability. Any other object as the first argument raises a `userns` type
  error, so to ask about a different task use that task's own check —
  `task:capable(cap)` or `cred:capable(cap)` from the `kernel` library.
  Calling with no arguments raises `"At least 1 argument is required."`.
- `cap` is the one net/cap object that is safe to keep: it stores
  `kernel_cap_t` **by value**, so it is a self-contained snapshot. Operators
  never mutate their operands; each returns a new `cap`.
- `<=` and `<` are subset tests, so they are partial orders. Two disjoint
  sets satisfy neither `a <= b` nor `b <= a`, and `not (a <= b)` does not
  imply `b < a`. Do not sort `cap` objects.
- `tostring(cap)` prints the address of the userdata, not the bits, so it is
  not useful for inspecting set contents.
- `==` only fires when both operands are `cap` userdata, so `cap == 5` is
  silently `false`.

  ```lua
  local capability = require("capability")
  local errno = require("errno")

  function M.capable(cred, ns, cap, opts)
    if cap == capability.CAP_SYS_MODULE then
      return false, errno.EPERM
    end
    return true
  end
  ```

### `signal`

`signal` is a constant-only table — it registers no functions at all. Load it
with `local signal = require("signal")` and use it to name the signal number
that hooks such as `task_kill` hand you.

| Method | Arguments | Returns | On failure |
|---|---|---|---|
| (none) | — | — | — |

**Notes.**

- The constants are generated the same way as `capability`'s: a
  `CONST_DEFINE(SIGxxx)` table walked by `setconst()`, with values taken from
  `<linux/signal.h>` in the building kernel and names kept in the kernel
  spelling — `signal.SIGKILL`, `signal.SIGTERM`, `signal.SIGSTOP`,
  `signal.SIGCHLD`, `signal.SIGSYS`.
- The table runs from `SIGHUP` to `SIGSYS`. Aliases are present and equal by
  value: `signal.SIGABRT == signal.SIGIOT` and
  `signal.SIGIO == signal.SIGPOLL`.
- Every value in the table is a number, so `pairs(signal)` enumerates the
  full set with no filtering:

  ```lua
  local signal = require("signal")
  local kernel = require("kernel")

  for name, value in pairs(signal) do
    kernel.pr_info(name .. " = " .. value)
  end
  ```

- There are no real-time signals (`SIGRTMIN`, `SIGRTMAX`), no `SIGUNUSED`, no
  `SIG_DFL` or `SIG_IGN`, and no number-to-name helper. Build a reverse table
  yourself if you need one, and remember it is ambiguous because of the two
  aliases.
- The numbers are those of the building architecture; several differ on MIPS,
  Alpha and SPARC. Always compare against `signal.SIGxxx`, never a literal.

### `errno`

`errno` carries the error constants a hook returns to deny an operation, plus
one lookup function. Load it with `local errno = require("errno")` — it is
the library nearly every policy needs, because a denial is
`return false, errno.EXXX`.

| Method | Arguments | Returns | On failure |
|---|---|---|---|
| `errno.errname(n)` | 1 integer; the sign you pass is the sign you get back | 1: string, the macro name — `"EPERM"` for a positive code, `"-EPERM"` for a negative one | `nil` for a code with no symbolic name |

**Notes.**

- The constants are generated by the same `setconst()` walk over a
  `CONST_DEFINE(name)` table, with values from `<linux/errno.h>` — in
  practice the `<asm-generic/errno-base.h>` block, `EPERM` through `ERANGE`.
  Names are the kernel spellings: `errno.EPERM`, `errno.EACCES`,
  `errno.EINVAL`, `errno.ENOMEM`, `errno.EAGAIN`.
- Nothing beyond that first block is present. `ENOSYS`, `EOPNOTSUPP`,
  `ELOOP`, `ENAMETOOLONG`, `EADDRINUSE`, `ECONNREFUSED` and the rest read as
  `nil`, and returning `nil` as a hook's second value is not a valid errno.
  Check the constant exists before you rely on it.
- Enumerate the real set the same way as for `capability`; `errname` shares
  the table, so filter on the value type:

  ```lua
  local errno = require("errno")
  local kernel = require("kernel")

  for name, value in pairs(errno) do
    if type(value) == "number" then
      kernel.pr_info(name .. " = " .. value)
    end
  end
  ```

- **The constants are positive**, which is what a hook return needs: write
  `return false, errno.EACCES`, and the LSM layer negates it for the kernel.
  Never negate it yourself in a hook return.
- `errname()` takes the constant in whichever sign you want the answer, because
  the kernel helper strips the leading minus only for a positive argument
  (`lib/errname.c:223`). So `errno.errname(errno.EPERM)` gives `"EPERM"` and
  `errno.errname(-errno.EPERM)` gives `"-EPERM"`, which is the spelling the
  `nil, err` pairs elsewhere in this API use. A code with no symbolic name,
  `errno.errname(0)` included, gives **`nil`** — not `"unknown"`, and not an
  error. A non-numeric argument raises, because the argument goes through
  `luaL_checkinteger`.
- The returned name is the bare kernel macro, with a leading minus if and only
  if you passed a negative code.
- The `nil, err` pairs other libraries return — kvcache writes, path
  lookups — already contain that name as a string in its leading-minus form and
  fall back to the literal `"unknown"` when the code is unrecognised
  (`security/lua/kvcache.c:129`). Those strings are for logging; the numeric
  `errno.*` constant is what you return.

  ```lua
  local errno = require("errno")
  local kernel = require("kernel")

  function M.socket_listen(sock, backlog)
    local sk = sock:sock()
    if sk == nil then return true end
    local ok, err = sk:kvcache_set("listening", true)
    if not ok then
      kernel.pr_warn("kvcache_set: " .. err)
      return false, errno.EPERM
    end
    return true
  end
  ```
