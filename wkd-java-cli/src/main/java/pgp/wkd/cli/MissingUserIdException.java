// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package pgp.wkd.cli;

/**
 * Exception that gets thrown when an OpenPGP certificate is not carrying a User-ID binding for the email address
 * that was used to look the certificate up via WKD.
 */
public class MissingUserIdException extends Exception {

    public MissingUserIdException() {
        super();
    }
}
