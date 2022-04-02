// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package pgp.wkd.test_suite;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.pgpainless.PGPainless;
import pgp.wkd.discovery.DiscoveryMethod;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.Path;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;

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

    protected PGPSecretKeyRing secretKey(String userId) throws PGPException, InvalidAlgorithmParameterException, NoSuchAlgorithmException {
        PGPSecretKeyRing secretKeys = PGPainless.generateKeyRing().modernKeyRing(userId, null);
        return secretKeys;
    }

    protected PGPPublicKeyRing certificate(String userId) throws PGPException, InvalidAlgorithmParameterException, NoSuchAlgorithmException {
        PGPSecretKeyRing secretKeys = secretKey(userId);
        PGPPublicKeyRing publicKeys = PGPainless.extractCertificate(secretKeys);
        return publicKeys;
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
