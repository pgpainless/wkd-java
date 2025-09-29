// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package pgp.wkd.cli;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.api.OpenPGPCertificate;
import org.bouncycastle.openpgp.api.OpenPGPKey;
import org.pgpainless.PGPainless;
import org.pgpainless.certificate_store.CertificateFactory;
import pgp.certificate_store.certificate.Certificate;
import pgp.wkd.CertificateAndUserIds;
import pgp.wkd.discovery.CertificateParser;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

public class PGPainlessCertificateParser implements CertificateParser {
    @Override
    public List<CertificateAndUserIds> read(InputStream inputStream) throws IOException {
        List<CertificateAndUserIds> certificatesAndUserIds = new ArrayList<>();
        try {
            List<OpenPGPCertificate> keyMaterial = PGPainless.getInstance().readKey().parseKeysOrCertificates(inputStream);
            if (keyMaterial.stream().anyMatch(it -> it instanceof OpenPGPKey)) {
                throw new PGPException("Secret key material encountered!");
            }
            for (OpenPGPCertificate certificate : keyMaterial) {
                Certificate parsedCert = CertificateFactory.certificateFromOpenPGPCertificate(certificate, 0L);
                List<String> userIds = certificate.getValidUserIds().stream().map(OpenPGPCertificate.OpenPGPUserId::getUserId).collect(Collectors.toList());
                certificatesAndUserIds.add(new CertificateAndUserIds(parsedCert, userIds));
            }
            return certificatesAndUserIds;
        } catch (PGPException e) {
            throw new IOException("Cannot parse certificates.", e);
        }
    }
}
