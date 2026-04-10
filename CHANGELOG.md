# Changelog

## [1.4.0](https://github.com/corazawaf/libcoraza/compare/v1.3.0...v1.4.0) (2026-04-10)


### Features

* add coraza_is_response_body_processable() API ([18498bd](https://github.com/corazawaf/libcoraza/commit/18498bd8bf517a1f6fcbe6c1205b3002471e13dd))
* add coraza_is_response_body_processable() API ([8767ebe](https://github.com/corazawaf/libcoraza/commit/8767ebeb4a708b5cf711fd4b3b0ae060c9c2ab71))


### Bug Fixes

* **tests:** update expected severity for coraza v3.7.0 ([627e13a](https://github.com/corazawaf/libcoraza/commit/627e13aeca94f1a555dea5ddba3727505cf999b7))
* **tests:** update expected severity for coraza v3.7.0 ([bc02f8b](https://github.com/corazawaf/libcoraza/commit/bc02f8bf6685df06defb342a61fea3e1436a2e99))

## [1.3.0](https://github.com/corazawaf/libcoraza/compare/v1.2.2...v1.3.0) (2026-04-07)


### Features

* add Python and Java callback trampolines via userContext ([ea27028](https://github.com/corazawaf/libcoraza/commit/ea27028cb69637c03a7307c0e13aa2c33fefa0cc))
* add SWIG support for generating multi-language bindings ([0586007](https://github.com/corazawaf/libcoraza/commit/0586007c4e1dacf8b96821afc6e756c0fad52820))


### Bug Fixes

* **ci:** install autotools on macOS runners for SWIG jobs ([01a226c](https://github.com/corazawaf/libcoraza/commit/01a226c5a4b065b9dccb391752a30f04f06489d2))
* **ci:** use Go 1.25.x/1.26.x to match go.mod minimum version requirement ([cc476dc](https://github.com/corazawaf/libcoraza/commit/cc476dc315049a615afe90c5895096e84b6910b6))
* correct %native cfg type and debug callback assertion ([15951bf](https://github.com/corazawaf/libcoraza/commit/15951bfb18fa5029699d2026e81ded4b4e10462d))
* correct SWIG Java type and macOS Python linker flags ([bbf40ab](https://github.com/corazawaf/libcoraza/commit/bbf40ab455220a0f1717b20c9108810498b89848))
* **deps:** update module github.com/corazawaf/coraza/v3 to v3.7.0 in go.mod ([#86](https://github.com/corazawaf/libcoraza/issues/86)) ([4ec85f9](https://github.com/corazawaf/libcoraza/commit/4ec85f9c9a6750e1e369da0be951ecf693f58348))
* **java:** make JNI library self-contained and macOS-compatible ([a477889](https://github.com/corazawaf/libcoraza/commit/a477889a492a6c4e68dfa6cd0163ad6612817c1a))
* SWIG interface and CI gaps from PR review ([716d594](https://github.com/corazawaf/libcoraza/commit/716d5940696248373ab671475b42f440eb332302))
* **swig:** add %exception to propagate TypeError from callback validators ([65dd99e](https://github.com/corazawaf/libcoraza/commit/65dd99e3d24ce399247abb02cb4f45a149c84de6))
* **swig:** harden SWIG layer against overflow, null deref, and memory leaks ([6248e60](https://github.com/corazawaf/libcoraza/commit/6248e600b98551af4487906107291fea375a3021))
* **swig:** ignore callback setters for Java to prevent SWIGTYPE_p_Object conflict ([ebf9a84](https://github.com/corazawaf/libcoraza/commit/ebf9a84973496b32f1ca574210ae0ee14204ce72))
* use version.txt for autoconf version instead of git-version-gen ([7bed87f](https://github.com/corazawaf/libcoraza/commit/7bed87ff4efc0afb8754ceec288fa234bef0bc16))

## [1.2.2](https://github.com/corazawaf/libcoraza/compare/v1.2.1...v1.2.2) (2026-03-31)


### Bug Fixes

* **deps:** update module github.com/corazawaf/coraza/v3 to v3.6.0 in go.mod ([#77](https://github.com/corazawaf/libcoraza/issues/77)) ([3848100](https://github.com/corazawaf/libcoraza/commit/38481005292839486affe2df8409438a6cd65f3e))

## [1.2.1](https://github.com/corazawaf/libcoraza/compare/v1.2.0...v1.2.1) (2026-03-28)


### Bug Fixes

* **deps:** update module github.com/corazawaf/coraza/v3 to v3.5.0 in go.mod ([#74](https://github.com/corazawaf/libcoraza/issues/74)) ([01ae755](https://github.com/corazawaf/libcoraza/commit/01ae75582bd83f1148d3f11060966bd5d058b803))

## [1.2.0](https://github.com/corazawaf/libcoraza/compare/v1.1.1...v1.2.0) (2026-03-19)


### Features

* add Debian packaging ([851e522](https://github.com/corazawaf/libcoraza/commit/851e522edf20737823dc6ba2132c543ea9434562))
* add Debian packaging ([a3db312](https://github.com/corazawaf/libcoraza/commit/a3db312f2e5c1d8429a1426f0e132e58fcfda4a6))

## [1.1.1](https://github.com/corazawaf/libcoraza/compare/v1.1.0...v1.1.1) (2026-03-15)


### Bug Fixes

* **deps:** update go modules in go.mod ([#64](https://github.com/corazawaf/libcoraza/issues/64)) ([5a6cd64](https://github.com/corazawaf/libcoraza/commit/5a6cd6420ee2c81421455ad1a55e6a2ff06dc9ee))
* **deps:** update module github.com/corazawaf/coraza/v3 to v3.4.0 in go.mod ([#65](https://github.com/corazawaf/libcoraza/issues/65)) ([4319bb0](https://github.com/corazawaf/libcoraza/commit/4319bb0decfc525f7150e32565c8c6dbbaa3fe95))
* MacOS build needs resolv ([406f008](https://github.com/corazawaf/libcoraza/commit/406f008fd62d43e43cf503b58e7d7345cfb0c672))

## [1.1.0](https://github.com/corazawaf/libcoraza/compare/v1.0.1...v1.1.0) (2026-03-01)


### Features

* add data field to coraza_intervention_t ([c49ed7f](https://github.com/corazawaf/libcoraza/commit/c49ed7ff2e3019ac934030d14ab7ecfc0db24298))

## [1.0.1](https://github.com/corazawaf/libcoraza/compare/v1.0.0...v1.0.1) (2026-02-28)


### Bug Fixes

* eliminate C string memory leaks in fuzz test iterations ([eab2df7](https://github.com/corazawaf/libcoraza/commit/eab2df77d408653fa688102a71daa2c30aeabf76))

## 1.0.0 (2026-02-27)


### Features

* add  coraza_add_get_args to expose tx.AddGetRequestArgument ([#34](https://github.com/corazawaf/libcoraza/issues/34)) ([994164a](https://github.com/corazawaf/libcoraza/commit/994164a69585e9d94c6c22a7fb4b61493b4b04f2))
* add handle types for WAF and Transaction types ([3f88f9d](https://github.com/corazawaf/libcoraza/commit/3f88f9d230544e1bbdf39444efb3ab4b47f70a9c))
* **ci:** update doxy build ([0e98dd5](https://github.com/corazawaf/libcoraza/commit/0e98dd5104dfd21747f08c1add03b8273097035b))
* **ci:** update doxy build ([76e78e9](https://github.com/corazawaf/libcoraza/commit/76e78e984901de7006e0945e26757ec969e08888))
* implement coraza_rules_count and coraza_update_status_code ([a7c41ab](https://github.com/corazawaf/libcoraza/commit/a7c41ab3248c373cc4e9f334230635040c86f707))
* implement registering error callbacks ([7d19b8d](https://github.com/corazawaf/libcoraza/commit/7d19b8d6f5f0741e79cf10b4e6ce743fa0207122))
* implement waf config type ([c0dd712](https://github.com/corazawaf/libcoraza/commit/c0dd712bf8444b1b6edb945d47e6e4cd5deb9dfc))
* **libcoraza:** rename directories and clean utils ([1f20d3e](https://github.com/corazawaf/libcoraza/commit/1f20d3ed5894a883dc9abc3e3c53c1e8821cdd26))
* support debugger callbacks ([5882ac3](https://github.com/corazawaf/libcoraza/commit/5882ac3a9dbf651ca98345640122e731709db533))


### Bug Fixes

* **ci:** do not install test bin ([4662aeb](https://github.com/corazawaf/libcoraza/commit/4662aeb429a83ca305d04e4104094afed2e5885d))
* **ci:** include all dep ([5e3d3ff](https://github.com/corazawaf/libcoraza/commit/5e3d3ff265c4c4c7d6c176f033bcc17e1111ab46))
* naming for osx and tests ([0dea8e7](https://github.com/corazawaf/libcoraza/commit/0dea8e7cf6235c213cd002db4e405e6e0c56b338))
* remove test from install ([fe0e2dd](https://github.com/corazawaf/libcoraza/commit/fe0e2dd04037de9192fd699914710146db5df1c6))
* update test and files to use coraza dir ([246754f](https://github.com/corazawaf/libcoraza/commit/246754f423e67c03f53cb7952ca2177da91b43ac))
* update test and files to use coraza dir ([e4be238](https://github.com/corazawaf/libcoraza/commit/e4be23882ee22b69779fff16e4eadcda58fff195))

### v0.1 - YYYY-MM-dd

* Added autotools mechanism
    @fzipi, @airween
* Initial release
