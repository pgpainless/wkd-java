// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package pgp.wkd.test_suite;


import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.pgpainless.PGPainless;
import org.pgpainless.key.protection.SecretKeyRingProtector;
import pgp.wkd.discovery.DiscoveryMethod;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.Path;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import java.util.Random;

public class TestSuiteGenerator {


    private final String domain;

    public TestSuiteGenerator(String domain) {
        this.domain = domain;
    }

    public TestSuite generateTestSuiteInDirectory(File directory, DiscoveryMethod method) throws Exception {
        WkdDirectoryStructure dirs = directoryStructureForMethod(directory, method);
        dirs.mkdirs();

        List<TestCase> tests = new ArrayList<>();
        tests.add(test_baseCase(dirs));
        tests.add(test_baseCaseMultipleCertificates(dirs));
        tests.add(test_wrongUserId(dirs));
        tests.add(test_noUserId(dirs));
        tests.add(test_unboundUserId(dirs));
        tests.addAll(test_baseCaseMultiUserIds(dirs));
        tests.add(test_secretKeyMaterial(dirs));
        tests.add(test_randomBytes(dirs));
        tests.add(test_missingCertificate(dirs));

        return new TestSuite("0.1", tests);
    }

    // TEST CASES

    private TestCase test_baseCase(WkdDirectoryStructure directoryStructure) throws Exception {
        String lookupMail = "base-case@" + domain;
        String userId = "WKD-Test Base Case <base-case@" + domain + ">";
        String description = "Certificate has a single, valid user-id '" + userId + "'";

        PGPPublicKeyRing publicKeys = certificate(userId);

        writeDataFor(lookupMail, directoryStructure, new DataSink() {
            @Override
            public void write(OutputStream outputStream) throws IOException {
                publicKeys.encode(outputStream);
            }
        });

        return TestCase.ok("Base Case", description, lookupMail, directoryStructure);
    }

    private List<TestCase> test_baseCaseMultiUserIds(WkdDirectoryStructure directoryStructure) throws Exception {
        String primaryLookupMail = "primary-uid@" + domain;
        String secondaryLookupMail = "secondary-uid@" + domain;
        String primaryUserId = "WKD-Test Primary User-ID <" + primaryLookupMail + ">";
        String secondaryUserId = "WKD-Test Secondary User-ID <" + secondaryLookupMail + ">";
        String primaryDescription = "Certificate has multiple, valid user-ids. Is looked up via primary user-id '" + primaryUserId + "' using mail address '" + primaryLookupMail + "'.";
        String secondaryDescription = "Certificate has multiple, valid user-ids. Is looked up via secondary user-id '" + secondaryUserId + "' using mail address '" + secondaryLookupMail + "'.";

        PGPSecretKeyRing secretKeys = PGPainless.generateKeyRing().modernKeyRing(primaryUserId, null);
        SecretKeyRingProtector protector = SecretKeyRingProtector.unprotectedKeys();
        secretKeys = PGPainless.modifyKeyRing(secretKeys)
                .addUserId(secondaryUserId, protector)
                .done();
        PGPPublicKeyRing publicKeys = PGPainless.extractCertificate(secretKeys);
        DataSink sink = new DataSink() {
            @Override
            public void write(OutputStream outputStream) throws IOException {
                publicKeys.encode(outputStream);
            }
        };

        writeDataFor(primaryLookupMail, directoryStructure, sink);
        writeDataFor(secondaryLookupMail, directoryStructure, sink);

        return Arrays.asList(
                TestCase.ok("Multi-User-ID - Primary User-ID Lookup",
                        primaryDescription, primaryLookupMail, directoryStructure),
                TestCase.ok("Multi-User-ID - Secondary User-ID Lookup",
                        secondaryDescription, secondaryLookupMail, directoryStructure)
        );
    }

    private TestCase test_baseCaseMultipleCertificates(WkdDirectoryStructure directoryStructure) throws Exception {
        String title = "Multiple Certificates";
        String description = "The result contains multiple certificates.";
        String lookupMail = "multiple-certificates@" + domain;
        String userId1 = "First Certificate <" + lookupMail + ">";
        String userId2 = "Second Certificate <" + lookupMail + ">";

        PGPPublicKeyRing cert1 = certificate(userId1);
        PGPPublicKeyRing cert2 = certificate(userId2);

        writeDataFor(lookupMail, directoryStructure, new DataSink() {
            @Override
            public void write(OutputStream outputStream) throws IOException {
                cert1.encode(outputStream);
                cert2.encode(outputStream);
            }
        });

        return TestCase.ok(title, description, lookupMail, directoryStructure);
    }

    private TestCase test_wrongUserId(WkdDirectoryStructure directoryStructure) throws Exception {
        String lookupMail = "wrong-userid@" + domain;
        String userId = "WKD-Test Different User-ID <different-userid@" + domain + ">";
        String description = "Certificate has a single, valid user-id '" + userId + "', but is deposited for mail address '" + lookupMail + "'.";
        PGPPublicKeyRing publicKeys = certificate(userId);

        writeDataFor(lookupMail, directoryStructure, new DataSink() {
            @Override
            public void write(OutputStream outputStream) throws IOException {
                publicKeys.encode(outputStream);
            }
        });

        return TestCase.fail("Wrong User-ID", description, lookupMail, directoryStructure);
    }

    private TestCase test_unboundUserId(WkdDirectoryStructure directoryStructure) throws Exception {
        String lookupMail = "unbound-userid@" + domain;
        String userId = "WKD-Test Unbound User-ID <" + lookupMail + ">";
        String description = "Certificate has a single User-ID '" + userId + "' without binding signature.";
        PGPPublicKeyRing publicKeys = certificate(userId);

        Iterator<PGPPublicKey> keyIterator = publicKeys.iterator();
        PGPPublicKey primaryKey = keyIterator.next();
        Iterator<PGPSignature> bindingSigs = primaryKey.getSignaturesForID(userId);
        while (bindingSigs.hasNext()) {
            primaryKey = PGPPublicKey.removeCertification(primaryKey, userId, bindingSigs.next());
        }

        List<PGPPublicKey> keys = new ArrayList<>();
        keys.add(primaryKey);
        while (keyIterator.hasNext()) {
            keys.add(keyIterator.next());
        }

        PGPPublicKeyRing certificateWithoutUserIdBinding = new PGPPublicKeyRing(keys);
        writeDataFor(lookupMail, directoryStructure, new DataSink() {
            @Override
            public void write(OutputStream outputStream) throws IOException {
                certificateWithoutUserIdBinding.encode(outputStream);
            }
        });

        return TestCase.fail("Unbound UserId", description, lookupMail, directoryStructure);
    }

    private TestCase test_noUserId(WkdDirectoryStructure directoryStructure) throws Exception {
        String lookupMail = "absent-userid@" + domain;
        String description = "Certificate has no user-id, but is deposited for mail address '" + lookupMail + "'.";
        // Generate certificate with temp user-id
        PGPPublicKeyRing publicKeys = certificate("DeleteMe");

        // delete user-id
        List<PGPPublicKey> keys = new ArrayList<>();
        Iterator<PGPPublicKey> publicKeyIterator = publicKeys.iterator();
        PGPPublicKey primaryKey = publicKeyIterator.next();
        primaryKey = PGPPublicKey.removeCertification(primaryKey, "DeleteMe");
        keys.add(primaryKey);
        while (publicKeyIterator.hasNext()) {
            keys.add(publicKeyIterator.next());
        }
        publicKeys = new PGPPublicKeyRing(keys);

        PGPPublicKeyRing finalPublicKeys = publicKeys;
        writeDataFor(lookupMail, directoryStructure, new DataSink() {
            @Override
            public void write(OutputStream outputStream) throws IOException {
                finalPublicKeys.encode(outputStream);
            }
        });

        return TestCase.fail("No User-ID", description, lookupMail, directoryStructure);
    }

    private TestCase test_secretKeyMaterial(WkdDirectoryStructure directoryStructure) throws Exception {
        String lookupMail = "test-secret-key@" + domain;
        String description = "Certificate file contains secret key material.";
        PGPSecretKeyRing secretKeys = secretKey("WKD-Test Secret Key <" + lookupMail + ">");

        writeDataFor(lookupMail, directoryStructure, new DataSink() {
            @Override
            public void write(OutputStream outputStream) throws IOException {
                secretKeys.encode(outputStream);
            }
        });

        return TestCase.fail("Secret Key Material", description, lookupMail, directoryStructure);
    }

    private TestCase test_randomBytes(WkdDirectoryStructure directoryStructure)
            throws IOException {
        String lookupMail = "random-bytes@" + domain;
        String description = "Certificate file contains random bytes.";

        Random random = new Random(); // No need for Secure Random here

        writeDataFor(lookupMail, directoryStructure, outputStream -> {
            byte[] buf = new byte[random.nextInt(65536)];
            random.nextBytes(buf);
            outputStream.write(buf);
        });

        return TestCase.fail("Random Bytes", description, lookupMail, directoryStructure);
    }

    private TestCase test_missingCertificate(WkdDirectoryStructure dirs) {
        String lookupMail = "missing-cert@" + domain;
        String title = "Missing certificate";
        String description = "There is no certificate for the lookup mail address '" + lookupMail + "'.";
        return TestCase.fail(title, description, lookupMail, dirs);
    }

    // INTERNAL METHODS

    private WkdDirectoryStructure directoryStructureForMethod(File directory, DiscoveryMethod method) {
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

    private PGPSecretKeyRing secretKey(String userId) throws PGPException, InvalidAlgorithmParameterException, NoSuchAlgorithmException {
        PGPSecretKeyRing secretKeys = PGPainless.generateKeyRing().modernKeyRing(userId, null);
        return secretKeys;
    }

    private PGPPublicKeyRing certificate(String userId) throws PGPException, InvalidAlgorithmParameterException, NoSuchAlgorithmException {
        PGPSecretKeyRing secretKeys = secretKey(userId);
        PGPPublicKeyRing publicKeys = PGPainless.extractCertificate(secretKeys);
        return publicKeys;
    }

    private void writeDataFor(String mailAddress, WkdDirectoryStructure directory, DataSink sink)
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

    private interface DataSink {

        /**
         * Write data into the {@link OutputStream}.
         *
         * @param outputStream output stream
         * @throws IOException in case of an IO error
         */
        void write(OutputStream outputStream) throws IOException;

    }

}
