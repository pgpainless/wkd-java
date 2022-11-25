// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package pgp.wkd.cli;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.pgpainless.PGPainless;
import org.pgpainless.certificate_store.CertificateFactory;
import org.pgpainless.key.info.KeyRingInfo;
import pgp.certificate_store.certificate.Certificate;
import pgp.wkd.CertificateAndUserIds;
import pgp.wkd.discovery.CertificateParser;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

public class PGPainlessCertificateParser implements CertificateParser {
    @Override
    public List<CertificateAndUserIds> read(InputStream inputStream) throws IOException {
        List<CertificateAndUserIds> certificatesAndUserIds = new ArrayList<>();
        try {
            PGPPublicKeyRingCollection certificates = PGPainless.readKeyRing().publicKeyRingCollection(inputStream);
            for (PGPPublicKeyRing certificate : certificates) {
                KeyRingInfo info = PGPainless.inspectKeyRing(certificate);
                Certificate parsedCert = CertificateFactory.certificateFromPublicKeyRing(certificate, 0L);
                List<String> userIds = info.getValidAndExpiredUserIds();
                certificatesAndUserIds.add(new CertificateAndUserIds(parsedCert, userIds));
            }
            return certificatesAndUserIds;
        } catch (PGPException e) {
            throw new IOException("Cannot parse certificates.", e);
        }
    }
}
