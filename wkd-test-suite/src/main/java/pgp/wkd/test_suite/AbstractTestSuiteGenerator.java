// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package pgp.wkd.test_suite;

import org.bouncycastle.openpgp.api.OpenPGPCertificate;
import org.bouncycastle.openpgp.api.OpenPGPKey;
import org.pgpainless.PGPainless;
import pgp.wkd.discovery.DiscoveryMethod;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.Path;

public class AbstractTestSuiteGenerator {
    protected final String domain;

    public AbstractTestSuiteGenerator(String domain) {
        this.domain = domain;
    }

    protected WkdDirectoryStructure directoryStructureForMethod(File directory, DiscoveryMethod method) {
        WkdDirectoryStructure structure;
        if (method == DiscoveryMethod.direct) {
            structure = new WkdDirectoryStructure.DirectMethod(directory, domain);
        } else if (method == DiscoveryMethod.advanced) {
            structure = new WkdDirectoryStructure.AdvancedMethod(directory, domain);
        } else {
            throw new IllegalArgumentException("Invalid value for parameter 'method'.");
        }
        return structure;
    }

    protected OpenPGPKey secretKey(String userId) {
        OpenPGPKey secretKey = PGPainless.getInstance().generateKey().modernKeyRing(userId);
        return secretKey;
    }

    protected OpenPGPCertificate certificate(String userId) {
        OpenPGPKey secretKeys = secretKey(userId);
        OpenPGPCertificate certificate = secretKeys.toCertificate();
        return certificate;
    }

    protected void writeDataFor(String mailAddress, WkdDirectoryStructure directory, TestSuiteGenerator.DataSink sink)
            throws IOException {
        Path path = directory.getRelativeCertificatePath(mailAddress);
        File file = directory.resolve(path);

        if (!file.exists() && !file.createNewFile()) {
            throw new IOException("Cannot create file " + file.getAbsolutePath());
        }

        try (FileOutputStream fileOut = new FileOutputStream(file)) {
            sink.write(fileOut);
        }
    }

    protected interface DataSink {

        /**
         * Write data into the {@link OutputStream}.
         *
         * @param outputStream output stream
         * @throws IOException in case of an IO error
         */
        void write(OutputStream outputStream) throws IOException;

    }
}
