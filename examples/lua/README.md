# libcoraza Lua SWIG example

A minimal Lua binding example for [libcoraza](https://github.com/corazawaf/libcoraza)
generated via [SWIG](https://www.swig.org).  The bindings are compatible with
standard Lua 5.4 and LuaJIT (as used by Kong/OpenResty).

## Prerequisites

* libcoraza built in the repository root (`make` from the root)
* SWIG 4.0+
* Lua 5.4 or LuaJIT 2.1 development headers

Install on Debian/Ubuntu:

```sh
sudo apt install swig lua5.4 liblua5.4-dev      # Lua 5.4
sudo apt install swig luajit libluajit-5.1-dev  # LuaJIT
```

Install on macOS (Homebrew):

```sh
brew install swig lua     # or: brew install swig luajit
```

To build and run against LuaJIT, pass `LUA=luajit` to `make`, e.g.
`make -C examples/lua run LUA=luajit`.

## Build

From the repository root, build libcoraza first if you haven't already:

```sh
./build.sh && ./configure && make
```

Then build the Lua extension from this directory:

```sh
cd examples/lua
make
```

Or equivalently from the repository root:

```sh
make -C examples/lua
```

## Run

```sh
cd examples/lua
make run
```

Or equivalently from the repository root:

```sh
make -C examples/lua run
```

## What the example covers

`simple_get.lua` exercises all SWIG-exported libcoraza functions:

| Category | Functions |
|----------|-----------|
| Config & WAF | `coraza_new_waf_config`, `coraza_rules_add`, `coraza_rules_add_file`, `coraza_new_waf`, `coraza_rules_count`, `coraza_free_waf_config`, `coraza_free_waf` |
| Transaction | `coraza_new_transaction`, `coraza_new_transaction_with_id`, `coraza_free_transaction` |
| Request processing | `coraza_process_connection`, `coraza_process_uri`, `coraza_add_request_header`, `coraza_add_get_args`, `coraza_process_request_headers`, `coraza_append_request_body`, `coraza_process_request_body`, `coraza_request_body_from_file` |
| Response processing | `coraza_process_response_headers`, `coraza_add_response_header`, `coraza_append_response_body`, `coraza_process_response_body`, `coraza_update_status_code` |
| Logging & intervention | `coraza_process_logging`, `coraza_intervention`, `coraza_free_intervention` |
| WAF merging | `coraza_rules_merge` |
| Callbacks | `coraza_set_error_callback`, `coraza_set_debug_log_callback`, `coraza_matched_rule_get_error_log`, `coraza_matched_rule_get_severity` |

## Kong / OpenResty usage

Load the module with `require` in your Lua code:

```lua
local coraza = require("coraza")

local cfg = coraza.coraza_new_waf_config()
coraza.coraza_rules_add(cfg, 'SecRule REMOTE_ADDR "@ipMatch 10.0.0.0/8" "id:1,phase:1,deny,status:403"')

-- Optional: register a callback to inspect matched rules
coraza.coraza_set_error_callback(cfg, function(rule_handle)
    local log = coraza.coraza_matched_rule_get_error_log(rule_handle)
    ngx.log(ngx.WARN, "WAF matched: ", log)
end)

local waf = coraza.coraza_new_waf(cfg)
coraza.coraza_free_waf_config(cfg)

-- Per-request processing
local tx = coraza.coraza_new_transaction(waf)
coraza.coraza_process_connection(tx, ngx.var.remote_addr, 0, ngx.var.server_name, 0)
coraza.coraza_process_uri(tx, ngx.var.request_uri, ngx.var.request_method, ngx.var.server_protocol)
coraza.coraza_process_request_headers(tx)

local it = coraza.coraza_intervention(tx)
if it ~= nil then
    local status = it.status
    coraza.coraza_free_intervention(it)
    coraza.coraza_free_transaction(tx)
    ngx.exit(status)
end

coraza.coraza_free_transaction(tx)
```

### Callback notes

* Callbacks fire synchronously during the libcoraza call that triggered them,
  and run on the Lua thread (coroutine) making that call, not the one that
  registered them. Registering callbacks once at startup and processing
  transactions in request handlers is safe.
* An error raised inside a callback is printed to stderr and otherwise
  ignored; transaction processing continues.
* Each registered callback holds a Lua registry reference and a small C
  allocation that are never released. Rebuilding the WAF on every config
  reload leaks one of each per callback, so register callbacks sparingly.

## Clean

```sh
make -C examples/lua clean
```
