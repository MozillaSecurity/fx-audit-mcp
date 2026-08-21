# CHANGELOG

<!-- version list -->

## v2.1.0 (2026-08-21)

### Bug Fixes

- Tolerate CLI output errors
  ([`19e7156`](https://github.com/MozillaSecurity/fx-audit-mcp/commit/19e715694d54f3c0812be171995bd062dfa5cc2d))

### Documentation

- Add process_output.py description and location
  ([`3a5fafc`](https://github.com/MozillaSecurity/fx-audit-mcp/commit/3a5fafc06f388a85c2d47e08537bb2f8f88fd6cd))

### Features

- Add streaming support for build_firefox output
  ([`ba477d7`](https://github.com/MozillaSecurity/fx-audit-mcp/commit/ba477d776c85c6f5dff044d6a42a351b6e9c9539))


## v2.0.0 (2026-08-19)

### Features

- **browser_evaluator**: Take testcase files as a single mapping
  ([`612dbb5`](https://github.com/MozillaSecurity/fx-audit-mcp/commit/612dbb530a0a6de8a92a396492d7b64904dd6704))


## v1.4.2 (2026-08-14)

### Bug Fixes

- **browser_evaluator**: Flag every crashed process, not just the first
  ([`a5100b0`](https://github.com/MozillaSecurity/fx-audit-mcp/commit/a5100b01f8a2ec1f24b60f97eb569b129df20097))


## v1.4.1 (2026-08-12)

### Bug Fixes

- **browser_evaluator**: Report child flags as False when the parent crashed
  ([`e09ad75`](https://github.com/MozillaSecurity/fx-audit-mcp/commit/e09ad757da47a2b2fb006c4af832db00ef535c72))


## v1.4.0 (2026-08-12)

### Features

- **browser_evaluator**: Add process types to crash info
  ([`5ea2d3a`](https://github.com/MozillaSecurity/fx-audit-mcp/commit/5ea2d3a200e21881b950a617a92bb894dbc318ce))


## v1.3.0 (2026-07-30)

### Features

- **browser_evaluator**: Add enable_sandbox argument
  ([`c8ea3b3`](https://github.com/MozillaSecurity/fx-audit-mcp/commit/c8ea3b30fcd02fa24fd1b5e4e0821ede2f234fa5))


## v1.2.4 (2026-07-20)

### Bug Fixes

- Bump build version to pickup pref changes
  ([`bb4774b`](https://github.com/MozillaSecurity/fx-audit-mcp/commit/bb4774b445053b09498988b0fdee5ddccc978808))

### Refactoring

- **prefs**: Remove _BASELINE_PREFS, rely on prefpicker template
  ([`98eb9d8`](https://github.com/MozillaSecurity/fx-audit-mcp/commit/98eb9d8e980a42505736ca16bb3882b3f785a272))


## v1.2.3 (2026-07-17)

### Bug Fixes

- **prefs**: Pickup variant improvements in prefpicker
  ([`e1496b3`](https://github.com/MozillaSecurity/fx-audit-mcp/commit/e1496b33a5a1d4f63fb31e2a24dee932d38ce043))


## v1.2.2 (2026-07-17)

### Bug Fixes

- **prefs**: Use code-review prefs variant in all cases
  ([`b449d03`](https://github.com/MozillaSecurity/fx-audit-mcp/commit/b449d03165c44e870db487cd80d33bcd0012d9b4))


## v1.2.1 (2026-07-15)

### Bug Fixes

- **prefs**: Use code-review prefs variant
  ([`6291c82`](https://github.com/MozillaSecurity/fx-audit-mcp/commit/6291c82e98aa58aaa691488290bf1950ba386f2f))


## v1.2.0 (2026-07-10)

### Features

- Add support for prefs blocklist
  ([`364e48b`](https://github.com/MozillaSecurity/fx-audit-mcp/commit/364e48b988f32a922ebe9defe4418a7b3b9809b6))


## v1.1.2 (2026-06-15)

### Bug Fixes

- Disable Nimbus via pref to reduce spam
  ([`c2b814d`](https://github.com/MozillaSecurity/fx-audit-mcp/commit/c2b814d0e1e7f2ba559da330a24d056d1f584a58))

- Remove invalid pref
  ([`e84c7f6`](https://github.com/MozillaSecurity/fx-audit-mcp/commit/e84c7f671bf660e1efe51c88b97541aae58198bb))


## v1.1.1 (2026-06-12)

### Bug Fixes

- Update prefs to disable unneeded functionality
  ([`b34078b`](https://github.com/MozillaSecurity/fx-audit-mcp/commit/b34078b21583de926811348f7ba889ff5d4faaac))

### Chores

- Update grizzly version
  ([`85f88d6`](https://github.com/MozillaSecurity/fx-audit-mcp/commit/85f88d6d7fcbf5373abd36d414eba0aae46b62c6))


## v1.1.0 (2026-06-04)

### Chores

- Update grizzly version
  ([`a09f35f`](https://github.com/MozillaSecurity/fx-audit-mcp/commit/a09f35fc4a12fdf2043c7ebb9d13e2d21a4ccd06))

### Continuous Integration

- Semantic release updates uv.lock
  ([`8b73786`](https://github.com/MozillaSecurity/fx-audit-mcp/commit/8b737863b26a771e8da82b6bacffd4e9feb4ea54))

### Features

- Remove unused bugzilla tools
  ([`d982761`](https://github.com/MozillaSecurity/fx-audit-mcp/commit/d98276170d3dd1047f4360cbb586665cf2adc799))


## v1.0.2 (2026-06-04)

### Bug Fixes

- Reduce log output from mesa
  ([`d1ce48e`](https://github.com/MozillaSecurity/fx-audit-mcp/commit/d1ce48e8fc2cc92550b2401a5725cce05cd73e0d))


## v1.0.1 (2026-05-25)

### Bug Fixes

- Pypi publishing
  ([`4718d54`](https://github.com/MozillaSecurity/fx-audit-mcp/commit/4718d5476a0e2e5fb80e8f4dcf144dec948115cc))


## v1.0.0 (2026-05-25)

- Initial Release
