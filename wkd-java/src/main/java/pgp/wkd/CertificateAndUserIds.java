// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package pgp.wkd;

import pgp.certificate_store.certificate.Certificate;

import java.util.ArrayList;
import java.util.List;

/**
 * Tuple class which bundles a {@link Certificate} and a list of its valid or expired user ids.
 */
public class CertificateAndUserIds {

    private final Certificate certificate;
    private final List<String> userIds;

    public CertificateAndUserIds(Certificate certificate, List<String> userIds) {
        this.certificate = certificate;
        this.userIds = userIds;
    }

    /**
     * Return a list containing the valid or expired user-ids of the certificate.
     *
     * @return user ids
     */
    public List<String> getUserIds() {
        return new ArrayList<>(userIds);
    }

    /**
     * Return the certificate itself.
     *
     * @return certificate
     */
    public Certificate getCertificate() {
        return certificate;
    }
}
