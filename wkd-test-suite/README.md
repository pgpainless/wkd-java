<!--
SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>

SPDX-License-Identifier: Apache-2.0
-->

# WKD Test Suite Generator

[![javadoc](https://javadoc.io/badge2/org.pgpainless/wkd-test-suite/javadoc.svg)](https://javadoc.io/doc/org.pgpainless/wkd-test-suite)
[![Maven Central](https://badgen.net/maven/v/maven-central/org.pgpainless/wkd-test-suite)](https://search.maven.org/artifact/org.pgpainless/wkd-test-suite)

This module contains a CLI application that can be used to generate WKD test vectors.

```shell
$ java -jar wkd-test-suite.jar help
Usage: wkd-test-suite [-hV] [--json-summary[=<jsonOutputFiles>]]...
                      [--xml-summary[=<xmlOutputFiles>]]... -d=<domain>
                      [-m={direct|advanced}] -o=<rootDir>
  -d, --domain=<domain>   Root domain
  -h, --help              Show this help message and exit.
      --json-summary[=<jsonOutputFiles>]
                          Write JSON summary to file
  -m, --method={direct|advanced}
                          Method for key discovery
  -o, --output-dir=<rootDir>
                          Output directory
  -V, --version           Print version information and exit.
      --xml-summary[=<xmlOutputFiles>]
                          Write XML summary to file
```

Example output summary.json:

```json
{
  "version" : "0.1",
  "testCases" : [ {
    "expectSuccess" : true,
    "testTitle" : "Base Case",
    "testDescription" : "Certificate has a single, valid user-id 'WKD-Test Base Case <base-case@pgpainless.github.io>'",
    "lookupMailAddress" : "base-case@pgpainless.github.io",
    "certificatePath" : ".well-known/openpgpkey/hu/6q1ubufxsqh8fjuewbachy5ocz9seanp",
    "lookupUri" : "https://pgpainless.github.io/.well-known/openpgpkey/hu/6q1ubufxsqh8fjuewbachy5ocz9seanp?l=base-case"
  }, {
    "expectSuccess" : false,
    "testTitle" : "Wrong User-ID",
    "testDescription" : "Certificate has a single, valid user-id 'WKD-Test Different User-ID <different-userid@pgpainless.github.io>', but is deposited for mail address 'wrong-userid@pgpainless.github.io'.",
    "lookupMailAddress" : "wrong-userid@pgpainless.github.io",
    "certificatePath" : ".well-known/openpgpkey/hu/87rxmyhh4paokf1apw6qiej8hk6nwuxy",
    "lookupUri" : "https://pgpainless.github.io/.well-known/openpgpkey/hu/87rxmyhh4paokf1apw6qiej8hk6nwuxy?l=wrong-userid"
  }, {
    "expectSuccess" : false,
    "testTitle" : "No User-ID",
    "testDescription" : "Certificate has no user-id, but is deposited for mail address 'absent-userid@pgpainless.github.io'.",
    "lookupMailAddress" : "absent-userid@pgpainless.github.io",
    "certificatePath" : ".well-known/openpgpkey/hu/caky1x1mawkc6gg4kge1icod96wqaeax",
    "lookupUri" : "https://pgpainless.github.io/.well-known/openpgpkey/hu/caky1x1mawkc6gg4kge1icod96wqaeax?l=absent-userid"
  }, {
    "expectSuccess" : true,
    "testTitle" : "Multi-User-ID - Primary User-ID Lookup",
    "testDescription" : "Certificate has multiple, valid user-ids. Is looked up via primary user-id 'WKD-Test Primary User-ID <primary-uid@pgpainless.github.io>' using mail address 'primary-uid@pgpainless.github.io'.",
    "lookupMailAddress" : "primary-uid@pgpainless.github.io",
    "certificatePath" : ".well-known/openpgpkey/hu/iz5jxf9oi1mbc1p45s3nxcuxn38qazkw",
    "lookupUri" : "https://pgpainless.github.io/.well-known/openpgpkey/hu/iz5jxf9oi1mbc1p45s3nxcuxn38qazkw?l=primary-uid"
  }, {
    "expectSuccess" : true,
    "testTitle" : "Multi-User-ID - Secondary User-ID Lookup",
    "testDescription" : "Certificate has multiple, valid user-ids. Is looked up via secondary user-id 'WKD-Test Secondary User-ID <secondary-uid@pgpainless.github.io>' using mail address 'secondary-uid@pgpainless.github.io'.",
    "lookupMailAddress" : "secondary-uid@pgpainless.github.io",
    "certificatePath" : ".well-known/openpgpkey/hu/34i6oasjuzeunw5uwam7yqbtit1rtmjp",
    "lookupUri" : "https://pgpainless.github.io/.well-known/openpgpkey/hu/34i6oasjuzeunw5uwam7yqbtit1rtmjp?l=secondary-uid"
  }, {
    "expectSuccess" : false,
    "testTitle" : "Secret Key Material",
    "testDescription" : "Certificate file contains secret key material.",
    "lookupMailAddress" : "test-secret-key@pgpainless.github.io",
    "certificatePath" : ".well-known/openpgpkey/hu/4uoqyth19ibwszqjaokiafhxc5sh6usu",
    "lookupUri" : "https://pgpainless.github.io/.well-known/openpgpkey/hu/4uoqyth19ibwszqjaokiafhxc5sh6usu?l=test-secret-key"
  } ]
}
```