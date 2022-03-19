// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package pgp.wkd.cli.test_suite;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.TestFactory;
import pgp.wkd.cli.WKDCLI;
import pgp.wkd.cli.command.Fetch;
import pgp.wkd.discovery.DiscoveryMethod;
import pgp.wkd.test_suite.TestCase;
import pgp.wkd.test_suite.TestSuite;
import pgp.wkd.test_suite.TestSuiteGenerator;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

public class TestSuiteTestRunner {

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
        suite = generator.generateTestSuiteInDirectory(tempFile, DiscoveryMethod.direct);

        // Fetch certificates from a local directory instead of the internetzzz.
        Fetch.fetcher = new DirectoryBasedCertificateFetcher(tempPath);
    }

    @TestFactory
    public Iterable<DynamicTest> testsFromTestSuite() {
        return suite.getTestCases()
                .stream()
                .map(TestSuiteTestRunner::toDynamicTest)
                .collect(Collectors.toList());
    }

    public static DynamicTest toDynamicTest(TestCase testCase) {
        return DynamicTest.dynamicTest(testCase.getTestTitle(), () -> {

            String mail = testCase.getLookupMailAddress();
            int exitCode = WKDCLI.execute(new String[] {
                    "fetch", "--armor", mail
            });

            if (testCase.isExpectSuccess()) {
                assertEquals(0, exitCode, testCase.getTestDescription());
            } else {
                assertNotEquals(0, exitCode, testCase.getTestDescription());
            }
        });
    }
}
