# CHANGELOG

<!-- version list -->

## v4.0.0 (2026-09-03)

### Bug Fixes

- Detect Windows NTSTATUS faults as crashes
  ([`993a01e`](https://github.com/MozillaSecurity/fx-audit-mcp/commit/993a01e7c51349fd1b9752ac3adee59d0cc89ae7))

- Point the launch-timeout error at the captured launch logs
  ([`784c27d`](https://github.com/MozillaSecurity/fx-audit-mcp/commit/784c27d30b4d1de537e26bd4affc45395599247f))

- Raise operational failures instead of returning messages
  ([`e4f7215`](https://github.com/MozillaSecurity/fx-audit-mcp/commit/e4f72152ef6f1e37d8a3bb37d9d02c7efe70c8bb))

- Raise when python3 is missing from PATH
  ([`e9202ad`](https://github.com/MozillaSecurity/fx-audit-mcp/commit/e9202ad5b55530cf3da32c4de9b12a8dff723ed4))

- Remove the browser log directory when a run leaves it empty
  ([`32040b2`](https://github.com/MozillaSecurity/fx-audit-mcp/commit/32040b2a3b82b07791b4ce5357f8168302dae518))

- Report a sanitizer crash found in a timed-out run
  ([`229e901`](https://github.com/MozillaSecurity/fx-audit-mcp/commit/229e9013ca60c085b797ea4c881207d75751633e))

- Report an idle browser at the time limit as a clean run
  ([`57c71bf`](https://github.com/MozillaSecurity/fx-audit-mcp/commit/57c71bfafa8d0f1fe9c3606df820b490f051a31e))

- Report bad build directories without a traceback
  ([`a85c87e`](https://github.com/MozillaSecurity/fx-audit-mcp/commit/a85c87ec1e7414c1c4feb731b37683fed8120fcf))

- Report bad build invocations without a traceback
  ([`7c65478`](https://github.com/MozillaSecurity/fx-audit-mcp/commit/7c65478f406d3225cbde1ed8423ee51e4af52616))

- Report hangs that produce no report as timed out
  ([`fd4adac`](https://github.com/MozillaSecurity/fx-audit-mcp/commit/fd4adac0dfcec0237f71347df08e8eea51db23ab))

- Report no crashdata when a fault leaves stderr empty
  ([`4327a37`](https://github.com/MozillaSecurity/fx-audit-mcp/commit/4327a3772ea0665a9d9eb7811a924ffb3a775915))

- Stop idle detection cutting runs short of their timeout
  ([`8cb5d1f`](https://github.com/MozillaSecurity/fx-audit-mcp/commit/8cb5d1f1026d6685ca11626cababc01fa8768542))

- Unify the tool and schema descriptions shown to the agent
  ([`ca5ec2d`](https://github.com/MozillaSecurity/fx-audit-mcp/commit/ca5ec2d403d478d80407c67a2f0ac13d60847300))

### Build System

- **deps**: Raise the pydantic floor to 2.7 for attribute docstrings
  ([`134894e`](https://github.com/MozillaSecurity/fx-audit-mcp/commit/134894ed67222ea61c0323eb822a5f961e84eaed))

### Documentation

- Describe the log-path, exit-code and timeout contract
  ([`99c8479`](https://github.com/MozillaSecurity/fx-audit-mcp/commit/99c8479263b7e7d2781a4f940c5f76e20d49c798))

### Features

- Drop the browser result message and raise on launch timeout
  ([`6cd5a3a`](https://github.com/MozillaSecurity/fx-audit-mcp/commit/6cd5a3af8d9c263c0799e6642a5c30f947b2d371))

- Drop the echoed testcase files from crash results
  ([`4d2c1d2`](https://github.com/MozillaSecurity/fx-audit-mcp/commit/4d2c1d258608af0341aecaa5fffc0fdf7e62b1ac))

- Report a browser hang as timed_out rather than an error
  ([`1a7383d`](https://github.com/MozillaSecurity/fx-audit-mcp/commit/1a7383dab32dafd84787eed9a878acf67081065c))

- Return log paths and exit codes from the build tools
  ([`4acf794`](https://github.com/MozillaSecurity/fx-audit-mcp/commit/4acf7946e04bfcbea54911226b1eff0f24800665))

- Run JS shell testcases through the shared process runner
  ([`f4c4bf4`](https://github.com/MozillaSecurity/fx-audit-mcp/commit/f4c4bf48ede615cd9bb541f7ebc4d277f0633bc4))

- Run NSS gtests through the shared process runner
  ([`6e0ebad`](https://github.com/MozillaSecurity/fx-audit-mcp/commit/6e0ebad599105ce6cf2643ad7ab19694e704a4a0))

- Run subprocesses with output written to disk
  ([`d0887ea`](https://github.com/MozillaSecurity/fx-audit-mcp/commit/d0887ea26d06e83378cab47d44c442c523138df8))

- **logs**: Add helpers for writing subprocess logs to disk
  ([`f6d955c`](https://github.com/MozillaSecurity/fx-audit-mcp/commit/f6d955cb1923a1d6a50946e0dd119f46363e5ebe))

- **models**: Split crash log paths from build log paths
  ([`de82828`](https://github.com/MozillaSecurity/fx-audit-mcp/commit/de828286ce019ce95f20c3756525688f0cc9e9ed))

### Refactoring

- **models**: Document model fields with attribute docstrings
  ([`66e193a`](https://github.com/MozillaSecurity/fx-audit-mcp/commit/66e193af452b38c992d3c01629ff168f7db8de2b))

### Testing

- Guard the tool schemas the agent sees
  ([`64727de`](https://github.com/MozillaSecurity/fx-audit-mcp/commit/64727ded0100d4042817878d9bf9be3e64456fbb))


## v3.0.0 (2026-08-24)

### Features

- **browser_evaluator**: Write untruncated logs to disk
  ([`e6d3aae`](https://github.com/MozillaSecurity/fx-audit-mcp/commit/e6d3aaed921f00d9b33c8ac6cd847aa9cbd42be1))

### Breaking Changes

- **browser_evaluator**: BrowserCrashInfo.logs has changed and grizzly-framework>=1.3.0 is now
  required for report_size_limit.


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
