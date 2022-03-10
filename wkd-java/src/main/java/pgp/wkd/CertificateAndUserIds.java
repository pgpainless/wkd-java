// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package pgp.wkd;

import pgp.certificate_store.Certificate;

import java.util.ArrayList;
import java.util.List;

public class CertificateAndUserIds {

    private final Certificate certificate;
    private final List<String> userIds;

    public CertificateAndUserIds(Certificate certificate, List<String> userIds) {
        this.certificate = certificate;
        this.userIds = userIds;
    }

    public List<String> getUserIds() {
        return new ArrayList<>(userIds);
    }

    public Certificate getCertificate() {
        return certificate;
    }
}
