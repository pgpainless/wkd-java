// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package pgp.wkd.exception;

public class MissingPolicyFileException extends RuntimeException {

    public MissingPolicyFileException(Throwable cause) {
        super(cause);
    }
}
