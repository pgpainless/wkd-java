// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package pgp.wkd.test_suite;


import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.pgpainless.PGPainless;
import org.pgpainless.key.protection.SecretKeyRingProtector;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.URI;
import java.nio.file.Path;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;

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
        tests.add(wrongUserId(structure));
        tests.add(noUserId(structure));
        tests.addAll(baseCaseMultiUserIds(structure));
        tests.add(secretKeyMaterial(structure));

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
        URI lookupUri = directoryStructure.getAddress(lookupMail);
        Path path = directoryStructure.getRelativeCertificatePath(lookupMail);
        File file = directoryStructure.resolve(path);
        if (!file.exists() && !file.createNewFile()) {
            throw new IOException("Cannot create file " + file.getAbsolutePath());
        }

        try (FileOutputStream fileOut = new FileOutputStream(file)) {
            publicKeys.encode(fileOut);
        }

        return new TestCase(true, "Base Case", description, lookupMail, path, lookupUri);
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

        Path primaryPath = directoryStructure.getRelativeCertificatePath(primaryLookupMail);
        Path secondaryPath = directoryStructure.getRelativeCertificatePath(secondaryLookupMail);
        File primaryFile = directoryStructure.resolve(primaryPath);
        File secondaryFile = directoryStructure.resolve(secondaryPath);

        if (!primaryFile.exists() && !primaryFile.createNewFile()) {
            throw new IOException("Cannot create file " + primaryFile.getAbsolutePath());
        }
        if (!secondaryFile.exists() && !secondaryFile.createNewFile()) {
            throw new IOException("Cannot create file " + secondaryFile.getAbsolutePath());
        }

        try (FileOutputStream fileOut = new FileOutputStream(primaryFile)) {
            publicKeys.encode(fileOut);
        }
        try (FileOutputStream fileOut = new FileOutputStream(secondaryFile)) {
            publicKeys.encode(fileOut);
        }

        return Arrays.asList(
                new TestCase(true, "Multi-User-ID - Primary User-ID Lookup",
                        primaryDescription, primaryLookupMail, primaryPath, directoryStructure.getAddress(primaryLookupMail)),
                new TestCase(true, "Multi-User-ID - Secondary User-ID Lookup",
                        secondaryDescription, secondaryLookupMail, secondaryPath, directoryStructure.getAddress(secondaryLookupMail))
        );
    }

    private TestCase wrongUserId(WkdDirectoryStructure directoryStructure) throws Exception {
        String lookupMail = "wrong-userid@" + domain;
        String userId = "WKD-Test Different User-ID <different-userid@" + domain + ">";
        String description = "Certificate has a single, valid user-id '" + userId + "', but is deposited for mail address '" + lookupMail + "'.";
        PGPPublicKeyRing publicKeys = certificate(userId);
        Path path = directoryStructure.getRelativeCertificatePath(lookupMail);
        File file = directoryStructure.resolve(path);

        if (!file.exists() && !file.createNewFile()) {
            throw new IOException("Cannot create file " + file.getAbsolutePath());
        }

        try (FileOutputStream fileOut = new FileOutputStream(file)) {
            publicKeys.encode(fileOut);
        }

        return new TestCase(false, "Wrong User-ID", description, lookupMail, path, directoryStructure.getAddress(lookupMail));
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


        Path path = directoryStructure.getRelativeCertificatePath(lookupMail);
        File file = directoryStructure.resolve(path);

        if (!file.exists() && !file.createNewFile()) {
            throw new IOException("Cannot create file " + file.getAbsolutePath());
        }

        try (FileOutputStream fileOut = new FileOutputStream(file)) {
            publicKeys.encode(fileOut);
        }

        return new TestCase(false, "No User-ID", description, lookupMail, path, directoryStructure.getAddress(lookupMail));
    }

    private TestCase secretKeyMaterial(WkdDirectoryStructure directoryStructure) throws Exception {
        String lookupMail = "test-secret-key@" + domain;
        String description = "Certificate file contains secret key material.";
        PGPSecretKeyRing secretKeys = PGPainless.generateKeyRing().modernKeyRing("WKD-Test Secret Key <" + lookupMail + ">", null);

        Path path = directoryStructure.getRelativeCertificatePath(lookupMail);
        File file = directoryStructure.resolve(path);

        if (!file.exists() && !file.createNewFile()) {
            throw new IOException("Cannot create file " + file.getAbsolutePath());
        }

        try (FileOutputStream fileOut = new FileOutputStream(file)) {
            secretKeys.encode(fileOut);
        }

        return new TestCase(false, "Secret Key Material", description, lookupMail, path, directoryStructure.getAddress(lookupMail));
    }

}
