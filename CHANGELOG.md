# Changelog

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
