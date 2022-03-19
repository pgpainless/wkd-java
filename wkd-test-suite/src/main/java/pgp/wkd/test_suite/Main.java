// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package pgp.wkd.test_suite;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.PropertyAccessor;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectWriter;
import com.fasterxml.jackson.databind.json.JsonMapper;
import com.fasterxml.jackson.dataformat.xml.XmlMapper;
import pgp.wkd.discovery.DiscoveryMethod;
import picocli.CommandLine;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

@CommandLine.Command(name = "wkd-test-suite", mixinStandardHelpOptions = true, version = "0.1")
public class Main implements Runnable {

    private static final Pattern PATTERN_DOMAIN = Pattern.compile("^[a-zA-Z0-9.-]+$");

    @CommandLine.Option(names = {"--output-dir", "-o"},
            description = "Output directory",
            required = true)
    private File rootDir;

    @CommandLine.Option(names = "--xml-summary",
            description = "Write XML summary to file",
            arity = "0..1")
    private List<File> xmlOutputFiles = new ArrayList<>();

    @CommandLine.Option(names = "--json-summary",
            description = "Write JSON summary to file",
            arity = "0..1")
    private List<File> jsonOutputFiles = new ArrayList<>();

    @CommandLine.Option(names = {"--domain", "-d"},
            description = "Root domain",
            required = true, arity = "1")
    private String domain;

    @CommandLine.Option(names = {"--method", "-m"},
            paramLabel = "{direct|advanced}",
            description = "Method for key discovery. If absent, assume direct.")
    private DiscoveryMethod method = DiscoveryMethod.direct;

    @CommandLine.Spec // injected by picocli
    CommandLine.Model.CommandSpec spec;

    public static void main(String[] args) {
        System.exit(new CommandLine(new Main()).execute(args));
    }

    @Override
    public void run() {
        validate();

        TestSuiteGenerator generator = new TestSuiteGenerator(domain);
        try {
            TestSuite suite = generator.generateTestSuiteInDirectory(rootDir, method);
            writeSummaries(suite);
        } catch (Exception e) {
            throw new AssertionError(e);
        }
    }

    private void validate() {
        if (missing(xmlOutputFiles) && missing(jsonOutputFiles)) {
            throw new CommandLine.ParameterException(spec.commandLine(),
                    "Missing option. At least on of '--xml-summary' or '--json-summary' options must be specified.");
        }
        if (!PATTERN_DOMAIN.matcher(domain).matches()) {
            throw new CommandLine.ParameterException(spec.commandLine(),
                    "Value of option '--domain' must be a valid domain string.");
        }
    }

    private boolean missing(List<?> list) {
        return list == null || list.isEmpty();
    }

    private void writeSummaries(TestSuite suite) {
        ObjectMapper xmlMapper = new XmlMapper();
        xmlMapper.setVisibility(PropertyAccessor.FIELD, JsonAutoDetect.Visibility.ANY);

        ObjectMapper jsonMapper = new JsonMapper();
        jsonMapper.setVisibility(PropertyAccessor.FIELD, JsonAutoDetect.Visibility.ANY);

        ObjectWriter xmlWriter = xmlMapper.writer().withDefaultPrettyPrinter();
        for (File destination : xmlOutputFiles) {
            writeSummary(suite, destination, xmlWriter);
        }

        ObjectWriter jsonWriter = jsonMapper.writer().withDefaultPrettyPrinter();
        for (File destination : jsonOutputFiles) {
            writeSummary(suite, destination, jsonWriter);
        }
    }

    private void writeSummary(TestSuite suite, File destination, ObjectWriter objWriter) {
        try {
            destination.createNewFile();
        } catch (IOException e) {
            // Skip?
            return;
        }

        try (FileOutputStream fileOut = new FileOutputStream(destination); OutputStreamWriter osWriter = new OutputStreamWriter(fileOut, Charset.forName("UTF8"))) {
            objWriter.writeValue(osWriter, suite);
        } catch (IOException e) {
            // Skip?
        }
    }

}
