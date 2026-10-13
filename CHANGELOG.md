# Changelog

## [0.1.1](https://github.com/dnsgateway/cert-manager-webhook-dnsgate/compare/v0.1.0...v0.1.1) (2026-10-13)


### Bug Fixes

* helm chart release ([cd40ac8](https://github.com/dnsgateway/cert-manager-webhook-dnsgate/commit/cd40ac88bfc8a7a3ca9c9dc775cc6bfd7467d556))
* helm chart release ([a7072c2](https://github.com/dnsgateway/cert-manager-webhook-dnsgate/commit/a7072c20a2fa6d50f4319bee087b26f539d6aa49))

## [0.1.0](https://github.com/dnsgateway/cert-manager-webhook-dnsgate/compare/v0.0.1...v0.1.0) (2026-10-13)


### Features

* add challenge values with the TTL the solver config names ([c0fa1ff](https://github.com/dnsgateway/cert-manager-webhook-dnsgate/commit/c0fa1ffcbeb9cc8cb42bcd285f9bdae76dcc8cd3))
* add conformance ([ee5658a](https://github.com/dnsgateway/cert-manager-webhook-dnsgate/commit/ee5658aba7160e7a3dcd9cbb4a23c31a73cd20ed))
* apply --log-level to the framework's klog lines through the webhook's own log format ([38e29f0](https://github.com/dnsgateway/cert-manager-webhook-dnsgate/commit/38e29f07767898b55118d285916b9da38ce5baca))
* build the Gateway client with an Egress Agent ([ba30237](https://github.com/dnsgateway/cert-manager-webhook-dnsgate/commit/ba3023761d7602e586acd8f8c7a6da5daf3dc17d))
* default GROUP_NAME to acme.dnsgate.link ([73cb10a](https://github.com/dnsgateway/cert-manager-webhook-dnsgate/commit/73cb10a122de1054d910586f475d8c165b52f27a)), closes [#2](https://github.com/dnsgateway/cert-manager-webhook-dnsgate/issues/2)
* github actions ([a0e8a87](https://github.com/dnsgateway/cert-manager-webhook-dnsgate/commit/a0e8a870ea9dac7030327f71c9b7970e69f7e7e4))
* initial commit ([ba1688a](https://github.com/dnsgateway/cert-manager-webhook-dnsgate/commit/ba1688ab0e5dcba83bab577abcfd237b5a814f8f))
* log every Present with the Challenge, the outcome and the duration ([404c212](https://github.com/dnsgateway/cert-manager-webhook-dnsgate/commit/404c212563263d79490ae46be573d72a52b55c59))
* name the cause of a failed Gateway call in the Challenge's status ([a6b4911](https://github.com/dnsgateway/cert-manager-webhook-dnsgate/commit/a6b4911f0fb7cfadf0b7f9fcd7f06db86bd50549))
* never retry a failed Gateway call ([83c6977](https://github.com/dnsgateway/cert-manager-webhook-dnsgate/commit/83c6977004862a1e0347ae1ab44a22dc7047faae))
* package webhook Helm chart and signed releases ([fd40cd6](https://github.com/dnsgateway/cert-manager-webhook-dnsgate/commit/fd40cd6dc3c927f2f27593098423427a74486f45))
* pass the solver config's egress on every PatchRecord ([3f6c102](https://github.com/dnsgateway/cert-manager-webhook-dnsgate/commit/3f6c102a59a89dfcb17ea3868ad3395201261e07))
* refuse a challenge that is not dns-01 or whose key is not a challenge value ([178641b](https://github.com/dnsgateway/cert-manager-webhook-dnsgate/commit/178641b43908e7650cd108e25f3cc9a39bc891f9))
* remove the challenge value on CleanUp ([f6742ec](https://github.com/dnsgateway/cert-manager-webhook-dnsgate/commit/f6742ece8db61e67feb00c7d910fb51634ac20e3))
* serialize calls per Challenge Target with an in-memory lock ([8da97cf](https://github.com/dnsgateway/cert-manager-webhook-dnsgate/commit/8da97cfefd21d24d75d319317b5037ecc14c290e)), closes [#6](https://github.com/dnsgateway/cert-manager-webhook-dnsgate/issues/6)
* solver presents the challenge value through the Gateway ([234a180](https://github.com/dnsgateway/cert-manager-webhook-dnsgate/commit/234a18017a4b75c87b7e12fd5a2a9137883bb275))
* webhook server with Gateway flags checked at startup ([3ade5f9](https://github.com/dnsgateway/cert-manager-webhook-dnsgate/commit/3ade5f9478116814c24095ee287e1970565e1e32))
* write in the zone the solver config names ([b73507d](https://github.com/dnsgateway/cert-manager-webhook-dnsgate/commit/b73507d378128e9e9031a2d2d6e7d648feae482e))


### Bug Fixes

* align k8s.io versions with cert-manager v1.21.2 ([d39b02e](https://github.com/dnsgateway/cert-manager-webhook-dnsgate/commit/d39b02e0c3eb423f2679d4635a9d6b641f20c1cd))
* deployments probes ([ebdd19c](https://github.com/dnsgateway/cert-manager-webhook-dnsgate/commit/ebdd19cb16a13b82f70c4e8be223b4c2ded99133))
* enhance webhook configuration ([7778f15](https://github.com/dnsgateway/cert-manager-webhook-dnsgate/commit/7778f15e846a308f728f3716d7a903cfe0516430))
* helm chart ([7660071](https://github.com/dnsgateway/cert-manager-webhook-dnsgate/commit/7660071fed646b3bbf86ba9ab931f3382ef00914))
* name no provider status when the Provider refused without one ([1e0980f](https://github.com/dnsgateway/cert-manager-webhook-dnsgate/commit/1e0980f850903e426e45bfa477c0ed46834e4d33))
* name no TTL when the Gateway refuses CleanUp's record ([f344581](https://github.com/dnsgateway/cert-manager-webhook-dnsgate/commit/f3445815f4781677a461643cba023d1bb21b7006))
* pin kube-openapi to the version k8s.io 0.37 builds with ([8c32230](https://github.com/dnsgateway/cert-manager-webhook-dnsgate/commit/8c3223074eaf9a3928604de06f92dd7d4d807c0a))
* refuse the root as the configured zone as an invalid solver config ([22a394d](https://github.com/dnsgateway/cert-manager-webhook-dnsgate/commit/22a394da700cca73d8fca9d0c71251658716fa3d))
* treat empty env as unset, check --gateway at startup, time only the Gateway round trip ([c267fd0](https://github.com/dnsgateway/cert-manager-webhook-dnsgate/commit/c267fd0216f050358b18fbbbde393823f69c8fef)), closes [#2](https://github.com/dnsgateway/cert-manager-webhook-dnsgate/issues/2)
