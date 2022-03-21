// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package pgp.wkd.discovery;

import pgp.certificate_store.Certificate;
import pgp.wkd.CertificateAndUserIds;
import pgp.wkd.exception.MissingPolicyFileException;
import pgp.wkd.exception.RejectedCertificateException;
import pgp.wkd.RejectedCertificate;
import pgp.wkd.WKDAddress;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

public class DefaultCertificateDiscoverer implements CertificateDiscoverer {

    protected final CertificateParser reader;
    protected final CertificateFetcher fetcher;

    public DefaultCertificateDiscoverer(CertificateParser reader, CertificateFetcher fetcher) {
        this.reader = reader;
        this.fetcher = fetcher;
    }

    @Override
    public DiscoveryResponse discover(DiscoveryMethod method, WKDAddress address) {
        DiscoveryResponse.Builder builder = DiscoveryResponse.builder(method, address);

        fetchPolicy(method, address, builder);
        fetchCertificates(method, address, builder);

        return builder.build();
    }

    private void fetchCertificates(DiscoveryMethod method, WKDAddress address, DiscoveryResponse.Builder builder) {
        try {
            InputStream certificateIn = fetcher.fetchCertificate(address, method);
            List<CertificateAndUserIds> fetchedCertificates = reader.read(certificateIn);

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
                            new RejectedCertificateException.MissingUserId("Certificate " + certificate.getFingerprint() +
                                    " does not contain user-id with email '" + email + "'")));
                } else {
                    acceptableCertificates.add(certificate);
                }
            }

            builder.setAcceptableCertificates(acceptableCertificates);
            builder.setRejectedCertificates(rejectedCertificates);

        } catch (IOException e) {
            builder.setFetchingFailure(e);
        }
    }

    private void fetchPolicy(DiscoveryMethod method, WKDAddress address, DiscoveryResponse.Builder builder) {
        try {
            InputStream policyIn = fetcher.fetchPolicy(address, method);
            WKDPolicy policy = WKDPolicy.fromInputStream(policyIn);
            builder.setPolicy(policy);
        } catch (IOException e) {
            builder.setMissingPolicyFileException(new MissingPolicyFileException(e));
        }
    }
}
