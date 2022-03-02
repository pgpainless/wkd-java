// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package pgp.wkd.test_suite;

import java.util.List;

public class TestSuite {

    final String version;
    final List<TestCase> testCases;

    public TestSuite(String version, List<TestCase> testCases) {
        this.version = version;
        this.testCases = testCases;
    }
}
