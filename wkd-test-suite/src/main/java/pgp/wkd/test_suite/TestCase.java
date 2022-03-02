// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package pgp.wkd.test_suite;

import java.net.URI;
import java.nio.file.Path;

public class TestCase {

    final boolean expectSuccess;
    final String testTitle;
    final String testDescription;
    final String lookupMailAddress;
    final String certificatePath;
    final URI lookupUri;

    public TestCase(boolean expectSuccess, String testTitle, String description, String lookupMailAddress, Path certificatePath, URI lookupUri) {
        this.expectSuccess = expectSuccess;
        this.testTitle = testTitle;
        this.testDescription = description;
        this.lookupMailAddress = lookupMailAddress;
        this.certificatePath = certificatePath.toString();
        this.lookupUri = lookupUri;
    }

    public boolean isExpectSuccess() {
        return expectSuccess;
    }

    public String getTestTitle() {
        return testTitle;
    }

    public String getTestDescription() {
        return testDescription;
    }

    public String getLookupMailAddress() {
        return lookupMailAddress;
    }

    public String getCertificatePath() {
        return certificatePath;
    }

    public URI getLookupUri() {
        return lookupUri;
    }
}
