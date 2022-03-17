// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package pgp.wkd.discovery;

public enum DiscoveryMethod {

    /**
     * Advanced method.
     * This is the preferred method which MUST be checked first.
     *
     * @see <a href="https://www.ietf.org/archive/id/draft-koch-openpgp-webkey-service-13.html#section-3.1-5">OpenPGP Web Key Directory: Advanced Method</a>
     */
    advanced,

    /**
     * Direct method.
     * This is the fallback method.
     *
     * @see <a href="https://www.ietf.org/archive/id/draft-koch-openpgp-webkey-service-13.html#section-3.1-10">OpenPGP web Key Directory: Direct Method</a>
     */
    direct
}
