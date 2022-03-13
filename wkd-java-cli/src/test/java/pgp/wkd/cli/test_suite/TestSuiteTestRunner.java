// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package pgp.wkd.cli.test_suite;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.platform.commons.logging.Logger;
import org.junit.platform.commons.logging.LoggerFactory;
import pgp.wkd.cli.WKDCLI;
import pgp.wkd.cli.command.Fetch;
import pgp.wkd.test_suite.TestCase;
import pgp.wkd.test_suite.TestSuite;
import pgp.wkd.test_suite.TestSuiteGenerator;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

public class TestSuiteTestRunner {

    private static final Logger LOGGER = LoggerFactory.getLogger(TestSuiteTestRunner.class);
    private static TestSuite suite;

    @BeforeAll
    public static void setup() throws Exception {
        // Temporary, directory based WKD
        Path tempPath = Files.createTempDirectory("wkd-test");
        File tempFile = tempPath.toFile();
        tempFile.deleteOnExit();

        // Generate test certificates inside the temp wkd
        String domain = "example.com";
        TestSuiteGenerator generator = new TestSuiteGenerator(domain);
        suite = generator.generateTestSuiteInDirectory(tempFile, TestSuiteGenerator.Method.direct);

        // Fetch certificates from a local directory instead of the internetzzz.
        Fetch.fetcher = new DirectoryBasedWkdFetcher(tempPath);
    }

    @Test
    void runTestsAgainstTestSuite() {
        for (TestCase testCase : suite.getTestCases()) {
            LOGGER.info(() -> "Execute Test Case '" + testCase.getTestTitle() + "'");
            String mail = testCase.getLookupMailAddress();

            int exitCode = WKDCLI.execute(new String[] {
                    "fetch", "--armor", mail
            });

            if (testCase.isExpectSuccess()) {
                assertEquals(0, exitCode, testCase.getTestDescription());
            } else {
                assertNotEquals(0, exitCode, testCase.getTestDescription());
            }
        }
    }
}
