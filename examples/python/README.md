# libcoraza Python SWIG example

A minimal Python binding example for [libcoraza](https://github.com/corazawaf/libcoraza)
generated via [SWIG](https://www.swig.org).

## Prerequisites

* libcoraza built in the repository root (`make` from the root)
* SWIG 4.0+
* Python 3 development headers

Install on Debian/Ubuntu:

```sh
sudo apt install swig python3-dev
```

## Build

From the repository root, build libcoraza first if you haven't already:

```sh
./build.sh && ./configure && make
```

Then build the Python extension from this directory:

```sh
cd examples/python
make
```

Or equivalently from the repository root:

```sh
make -C examples/python
```

## Run

```sh
cd examples/python
make run
```

Or equivalently from the repository root:

```sh
make -C examples/python run
```

## What the example covers

`simple_get.py` exercises all SWIG-exported libcoraza functions testable without a
native callback:

| Category | Functions |
|----------|-----------|
| Config & WAF | `coraza_new_waf_config`, `coraza_rules_add`, `coraza_rules_add_file`, `coraza_new_waf`, `coraza_rules_count`, `coraza_free_waf_config`, `coraza_free_waf` |
| Transaction | `coraza_new_transaction`, `coraza_new_transaction_with_id`, `coraza_free_transaction` |
| Request processing | `coraza_process_connection`, `coraza_process_uri`, `coraza_add_request_header`, `coraza_add_get_args`, `coraza_process_request_headers`, `coraza_append_request_body`, `coraza_process_request_body`, `coraza_request_body_from_file` |
| Response processing | `coraza_process_response_headers`, `coraza_add_response_header`, `coraza_append_response_body`, `coraza_process_response_body`, `coraza_update_status_code` |
| Logging & intervention | `coraza_process_logging`, `coraza_intervention`, `coraza_free_intervention` |
| WAF merging | `coraza_rules_merge` |

> **Note:** `coraza_add_debug_log_callback` and `coraza_add_error_callback` are excluded
> from the default SWIG wrapper because function-pointer handling is language-specific.
> See the [SWIG documentation](https://www.swig.org/Doc4.2/Python.html) for details.

## Clean

```sh
make -C examples/python clean
```
