// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package pgp.wkd.test_suite;

import java.net.URI;
import java.nio.file.Path;

public class TestCase {

    enum Expectation {
        success,
        failure,
        unassertive
    }

    final Expectation expectation;
    final String testTitle;
    final String testDescription;
    final String lookupMailAddress;
    final String certificatePath;
    final URI lookupUri;

    public TestCase(Expectation expectation, String testTitle, String description, String lookupMailAddress, Path certificatePath, URI lookupUri) {
        this.expectation = expectation;
        this.testTitle = testTitle;
        this.testDescription = description;
        this.lookupMailAddress = lookupMailAddress;
        this.certificatePath = certificatePath.toString();
        this.lookupUri = lookupUri;
    }

    public static TestCase ok(String title, String description, String lookupMail, WkdDirectoryStructure structure) {
        Path filePath = structure.getRelativeCertificatePath(lookupMail);
        URI certUri = structure.getAddress(lookupMail);
        return new TestCase(Expectation.success, title, description, lookupMail, filePath, certUri);
    }

    public static TestCase fail(String title, String description, String lookupMail, WkdDirectoryStructure structure) {
        Path filePath = structure.getRelativeCertificatePath(lookupMail);
        URI certUri = structure.getAddress(lookupMail);
        return new TestCase(Expectation.failure, title, description, lookupMail, filePath, certUri);
    }

    public boolean isExpectSuccess() {
        return expectation == Expectation.success;
    }

    public boolean isExpectFailure() {
        return expectation == Expectation.failure;
    }

    public boolean isUnassertive() {
        return expectation == Expectation.unassertive;
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
