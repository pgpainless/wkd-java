// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package pgp.wkd.discovery;

import pgp.wkd.CertificateAndUserIds;

import java.io.IOException;
import java.io.InputStream;
import java.util.List;

/**
 * Interface for an OpenPGP certificate parser class.
 */
public interface CertificateParser {

    /**
     * Read a list of OpenPGP certificates from the given input stream.
     * The input stream contains binary OpenPGP certificate data.
     *
     * The result is a list of {@link CertificateAndUserIds}, where {@link CertificateAndUserIds#getUserIds()} only
     * contains validly bound user-ids.
     *
     * @param inputStream input stream of binary OpenPGP certificates
     * @return list of parsed certificates and their user-ids
     *
     * @throws IOException in case of an IO error
     */
    List<CertificateAndUserIds> read(InputStream inputStream) throws IOException;
}
