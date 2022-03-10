// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package pgp.wkd;

import pgp.certificate_store.Certificate;

public class RejectedCertificate {

    private final Certificate certificate;
    private final Throwable failure;

    public RejectedCertificate(Certificate certificate, Throwable failure) {
        this.certificate = certificate;
        this.failure = failure;
    }

    public Certificate getCertificate() {
        return certificate;
    }

    public Throwable getFailure() {
        return failure;
    }
}
