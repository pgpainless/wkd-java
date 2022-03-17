// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package pgp.wkd;

import pgp.certificate_store.Certificate;

/**
 * A rejected OpenPGP certificate.
 * The WKD specification requires that a certificate fetched via the Web Key Directory MUST contain the mail address
 * that was used to look up the certificate as a user id.
 *
 * A rejected certificate may not have carried the lookup email address.
 */
public class RejectedCertificate {

    private final Certificate certificate;
    private final Throwable reasonForRejection;

    public RejectedCertificate(Certificate certificate, Throwable reasonForRejection) {
        this.certificate = certificate;
        this.reasonForRejection = reasonForRejection;
    }

    /**
     * Return the certificate.
     * @return certificate
     */
    public Certificate getCertificate() {
        return certificate;
    }

    /**
     * Return the reason for rejection.
     * @return rejection reason
     */
    public Throwable getReasonForRejection() {
        return reasonForRejection;
    }
}
