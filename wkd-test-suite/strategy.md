<!--
SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>

SPDX-License-Identifier: Apache-2.0
-->

# WKD Test Suite

The purpose of the WKD test suite is to generate a set of certificates which can be published to a WKD.
The certificates cover different scenarios and edge cases and can be used to validate WKD implementations experimentally.

## Test Vectors

| Test Case                         | Description                                                                            |
|-----------------------------------|----------------------------------------------------------------------------------------|
| Base Case                         | Certificate with a single valid user-id A identified by A                              |
| Advanced Base Case                | Certificate with multiple user-ids A and B identified by A, B                          |
| Wrong User-ID                     | Certificate with a single valid user-id A identified by B                              |
| Missing User-ID                   | Certificate without a user-id identified by A                                          |
| Unbound User-ID                   | Certificate with a single unbound user-id A identified by A                            |
| Expired User-ID                   | Certificate with a single expired user-id A identified by A                            |
| Invalidly bound User-ID           | Certificate with a single user-id A with broken binding identified by A                |
| Revoked User-ID                   | Certificate with a single revoked user-id A identified by A                            |
| Revoked Certificate               | Certificate with a single user-id A, with direct-key revocation identified by A        |
| Third-Party User-ID               | Certificate with an additional user-id B certified by third party, identified by B     |
| Broken Data                       | Certificate file contains garbage                                                      |
| Secret Key                        | Certificate file contains secret key material                                          |
| Signatures                        | Certificate file contains certification signatures only                                |
| Multiple Certificates             | Certificate file contains multiple certificates (with valid user-id A) identified by A |
| Armored Certificate               | Certificate file contains armored certificate                                          |
| Duplicate mail address in user-id | Certificate contains user-id of form ".*<A>.*<B>.*"                                    |
