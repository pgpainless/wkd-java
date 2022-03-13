// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package pgp.wkd.test_suite;


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

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.pgpainless.PGPainless;
import org.pgpainless.key.protection.SecretKeyRingProtector;

public class TestSuiteGenerator {

    public enum Method {
        direct,
        advanced
    }

    private final String domain;

    public TestSuiteGenerator(String domain) {
        this.domain = domain;
    }

    public TestSuite generateTestSuiteInDirectory(File directory, Method method) throws Exception {
        WkdDirectoryStructure structure = directoryStructureForMethod(directory, method);
        structure.mkdirs();

        List<TestCase> tests = new ArrayList<>();
        tests.add(baseCase(structure));
        tests.add(baseCaseMultipleCertificates(structure));
        tests.add(wrongUserId(structure));
        tests.add(noUserId(structure));
        tests.add(unboundUserId(structure));
        tests.addAll(baseCaseMultiUserIds(structure));
        tests.add(secretKeyMaterial(structure));
        tests.add(randomBytes(structure));

        return new TestSuite("0.1", tests);
    }

    private WkdDirectoryStructure directoryStructureForMethod(File directory, Method method) {
        WkdDirectoryStructure structure;
        if (method == Method.direct) {
            structure = new WkdDirectoryStructure.DirectMethod(directory, domain);
        } else if (method == Method.advanced) {
            structure = new WkdDirectoryStructure.AdvancedMethod(directory, domain);
        } else {
            throw new IllegalArgumentException("Invalid value for parameter 'method'.");
        }
        return structure;
    }

    private PGPPublicKeyRing certificate(String userId) throws PGPException, InvalidAlgorithmParameterException, NoSuchAlgorithmException {
        PGPSecretKeyRing secretKeys = PGPainless.generateKeyRing().modernKeyRing(userId, null);
        PGPPublicKeyRing publicKeys = PGPainless.extractCertificate(secretKeys);
        return publicKeys;
    }

    private TestCase baseCase(WkdDirectoryStructure directoryStructure) throws Exception {
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

        return TestCase.ok("Base Csae", description, lookupMail, directoryStructure);
    }

    private List<TestCase> baseCaseMultiUserIds(WkdDirectoryStructure directoryStructure) throws Exception {
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

    private TestCase baseCaseMultipleCertificates(WkdDirectoryStructure directoryStructure) throws Exception {
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

    private TestCase wrongUserId(WkdDirectoryStructure directoryStructure) throws Exception {
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

    private TestCase unboundUserId(WkdDirectoryStructure directoryStructure) throws Exception {
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

    private TestCase noUserId(WkdDirectoryStructure directoryStructure) throws Exception {
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

    private TestCase secretKeyMaterial(WkdDirectoryStructure directoryStructure) throws Exception {
        String lookupMail = "test-secret-key@" + domain;
        String description = "Certificate file contains secret key material.";
        PGPSecretKeyRing secretKeys = PGPainless.generateKeyRing().modernKeyRing("WKD-Test Secret Key <" + lookupMail + ">", null);

        writeDataFor(lookupMail, directoryStructure, new DataSink() {
            @Override
            public void write(OutputStream outputStream) throws IOException {
                secretKeys.encode(outputStream);
            }
        });

        return TestCase.fail("Secret Key Material", description, lookupMail, directoryStructure);
    }

    private TestCase randomBytes(WkdDirectoryStructure directoryStructure) throws IOException {
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
        void write(OutputStream outputStream) throws IOException;
    }

}
