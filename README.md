<!--
SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>

SPDX-License-Identifier: Apache-2.0
-->

# Web Key Directory for Java

[![status-badge](https://ci.codeberg.org/api/badges/PGPainless/wkd-java/status.svg)](https://ci.codeberg.org/PGPainless/wkd-java)
[![Coverage Status](https://coveralls.io/repos/github/pgpainless/wkd-java/badge.svg?branch=main)](https://coveralls.io/github/pgpainless/wkd-java?branch=main)
[![REUSE status](https://api.reuse.software/badge/github.com/pgpainless/wkd-java)](https://api.reuse.software/info/github.com/pgpainless/wkd-java)

Client-side API for fetching OpenPGP certificates via the [Web Key Directory](https://www.ietf.org/archive/id/draft-koch-openpgp-webkey-service-13.html) protocol.

## Modules

This repository consists of the following modules:

* [wkd-java](/wkd-java): An implementation of Certificate Discovery
* [wkd-java-cli](/wkd-java-cli): A command line application for Certificate Discovery
* [wkd-test-suite](/wkd-test-suite): A test suite generator that can populate a WKD with test vectors
