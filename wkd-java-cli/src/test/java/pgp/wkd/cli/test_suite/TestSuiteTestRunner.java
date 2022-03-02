// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package pgp.wkd.cli.test_suite;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import pgp.wkd.cli.WKDCLI;
import pgp.wkd.cli.command.Fetch;
import pgp.wkd.test_suite.TestCase;
import pgp.wkd.test_suite.TestSuite;
import pgp.wkd.test_suite.TestSuiteGenerator;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

public class TestSuiteTestRunner {

    private static TestSuite suite;

    @BeforeAll
    public static void setup() throws Exception {
        Path tempDir = Files.createTempDirectory("wkd-test");
        tempDir.toFile().deleteOnExit();
        Fetch.fetcher = new DirectoryBasedWkdFetcher(tempDir);

        String domain = "example.com";

        TestSuiteGenerator generator = new TestSuiteGenerator(domain);
        suite = generator.generateTestSuiteInDirectory(tempDir.toFile(), TestSuiteGenerator.Method.direct);
    }

    @Test
    public void runTestsAgainstTestSuite() {
        for (TestCase testCase : suite.getTestCases()) {
            System.out.println("Executing test " + testCase.getTestTitle());
            int exitCode = WKDCLI.execute(new String[] {
                    "fetch", "--armor", testCase.getLookupMailAddress()
            });

            if (testCase.isExpectSuccess()) {
                assertEquals(0, exitCode);
            } else {
                assertNotEquals(0, exitCode);
            }
        }
    }
}
