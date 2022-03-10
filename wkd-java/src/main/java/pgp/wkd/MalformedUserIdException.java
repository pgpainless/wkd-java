// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package pgp.wkd;

public class MalformedUserIdException extends RuntimeException {

    public MalformedUserIdException(String message) {
        super(message);
    }
}
