// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package pgp.wkd.discovery;

import pgp.wkd.CertificateAndUserIds;

import java.io.IOException;
import java.io.InputStream;
import java.util.List;

public interface CertificateParser {

    List<CertificateAndUserIds> read(InputStream inputStream) throws IOException;
}
