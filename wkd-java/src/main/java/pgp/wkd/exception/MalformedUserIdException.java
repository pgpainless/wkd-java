// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package pgp.wkd.exception;

/**
 * Exception that gets thrown when the application is presented with a malformed user-id.
 * A malformed user-id is a user-id which does not contain an email address.
 */
public class MalformedUserIdException extends RuntimeException {

    public MalformedUserIdException(String message) {
        super(message);
    }
}
