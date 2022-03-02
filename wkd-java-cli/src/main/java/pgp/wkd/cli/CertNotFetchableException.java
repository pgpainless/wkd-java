// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package pgp.wkd.cli;

public class CertNotFetchableException extends RuntimeException {

    public static final int ERROR_CODE = 3;

    public CertNotFetchableException(String message) {
        super(message);
    }

    public CertNotFetchableException(String message, Throwable e) {
        super(message, e);
    }
}
