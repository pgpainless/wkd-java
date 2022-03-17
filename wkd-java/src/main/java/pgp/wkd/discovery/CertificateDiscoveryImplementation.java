// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package pgp.wkd.discovery;

import pgp.certificate_store.Certificate;
import pgp.wkd.CertificateAndUserIds;
import pgp.wkd.MissingUserIdException;
import pgp.wkd.RejectedCertificate;
import pgp.wkd.WKDAddress;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

public class CertificateDiscoveryImplementation implements CertificateDiscoverer {

    protected final CertificateParser reader;
    protected final CertificateFetcher fetcher;

    public CertificateDiscoveryImplementation(CertificateParser reader, CertificateFetcher fetcher) {
        this.reader = reader;
        this.fetcher = fetcher;
    }

    @Override
    public DiscoveryResponse discover(DiscoveryMethod method, WKDAddress address) {
        try {
            InputStream inputStream = fetcher.fetchCertificate(address, method);
            List<CertificateAndUserIds> fetchedCertificates = reader.read(inputStream);

            List<RejectedCertificate> rejectedCertificates = new ArrayList<>();
            List<Certificate> acceptableCertificates = new ArrayList<>();

            String email = address.getEmail();

            for (CertificateAndUserIds certAndUserIds : fetchedCertificates) {
                Certificate certificate = certAndUserIds.getCertificate();
                boolean containsEmail = false;
                for (String userId : certAndUserIds.getUserIds()) {
                    if (userId.contains("<" + email + ">") || userId.equals(email)) {
                        containsEmail = true;
                        break;
                    }
                }
                if (!containsEmail) {
                    rejectedCertificates.add(new RejectedCertificate(certificate,
                            new MissingUserIdException("Certificate " + certificate.getFingerprint() +
                                    " does not contain user-id with email '" + email + "'")));
                } else {
                    acceptableCertificates.add(certificate);
                }
            }

            return DiscoveryResponse.success(method, address, acceptableCertificates, rejectedCertificates);

        } catch (IOException e) {
            return DiscoveryResponse.failure(method, address, e);
        }
    }
}
