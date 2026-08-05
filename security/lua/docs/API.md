# API

## Module format

A module is a Lua chunk that returns a table with metadata and hook functions.

Required fields:
- `name` (string)
- `author` (string)
- `description` (string)
- `license` (string)
- `version` (number)

Hook functions are keyed by the supported LSM hook name (e.g. `file_open`).
Use `kernel.lsm_funcs()` to enumerate the supported set. Lua-LSM does not
expose unsupported hooks through its module APIs or observability output;
the current unsupported set includes `getprocattr`, `setprocattr`, and
`lsmprop_to_secctx`.

Example:

```lua
local errno = require("errno")

return {
  name = "demo",
  author = "example",
  description = "Example module",
  license = "GPL-2.0",
  version = 1,

  file_open = function(file, cred)
    local path = file:path()
    if path and path:match("^/etc/shadow$") then
      return false, errno.EPERM
    end
    return true
  end,
}
```

## Hook return values (int-return hooks)

- `nil` or no return: default value
- `true`: allow (0)
- `false`: deny (-EPERM)
- `false, errno`: deny (-errno)
- `nil, errno`: deny (-errno)

Use `require("errno")` to access errno constants.

## Listing hook names

From Lua:

```lua
local kernel = require("kernel")
local hooks = kernel.lsm_funcs()
```

From userspace (if stats enabled):

```
cat /sys/kernel/security/lua/lsm_funcs
```

Both interfaces list only hooks that Lua-LSM actually supports and registers.

## Built-in libraries

Lua-LSM preloads these libraries (use `require()`):

- `kernel`: task, cred, printk, time, and helper utilities
- `fs`: file/dentry/inode/path helpers
- `net`: socket and address helpers
- `errno`: errno constants + `errname()`
- `capability`: kernel capability helpers
- `signal`: signal helpers

## Common object methods (examples)

Task (`task`):
- `task:pids()` -> pid, tgid
- `task:comm()` -> comm string
- `task:cred()` -> cred object

File (`file`):
- `file:path()` -> path string or nil, err
- `file:inode()` -> inode object

Inode (`inode`):
- `inode:ino()` -> inode number
- `inode:mode()` -> table or boolean checks
- `inode:ids()` -> uid, gid

Dentry (`dentry`):
- `dentry:path()` -> path string

Sock (`sock`):
- `sock:suites()` -> family, type, protocol strings
- `sock:proto()` -> raw `sk_protocol` number, needed for non-IP protocol
  namespaces such as netlink's `NETLINK_GENERIC`

Skb (`skb`):
- `skb:sock()` -> owning sock, or `nil`. Always a full sock: a half-open
  (`SYN_RECV`) connection resolves to its listening sock and a time-wait sock
  yields `nil`, because those mini-sock forms lack the fields the `sock`
  accessors read
- `skb:len()` -> payload length
- `skb:read(off, len)` -> `len` bytes as a string (`len` <= 256), or `nil` when
  out of range

`skb:read()` returns raw bytes; decode multi-byte fields in Lua (e.g. with
`string.byte`), since the in-kernel Lua has no bit library. Reads are
bounds-checked and return `nil` instead of raising, so the policy decides the
verdict. Note that a Lua error inside a hook falls back to that hook's default
return value, which is "allow" for most hooks; wrap parsing in `pcall()` when
the policy must fail closed.

For a full list, see the method tables in `lua_kernel.c`, `lua_fs.c`, and
`lua_net.c`.
