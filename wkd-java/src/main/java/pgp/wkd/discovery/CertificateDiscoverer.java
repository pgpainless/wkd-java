// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package pgp.wkd.discovery;

import pgp.wkd.exception.MalformedUserIdException;
import pgp.wkd.WKDAddress;
import pgp.wkd.WKDAddressHelper;

import java.util.ArrayList;
import java.util.List;

public interface CertificateDiscoverer {

    DiscoveryResponse discover(DiscoveryMethod method, WKDAddress address);

    default DiscoveryResult discover(WKDAddress address) {
        List<DiscoveryResponse> results = new ArrayList<>();

        // advanced method
        DiscoveryResponse advanced = discover(DiscoveryMethod.advanced, address);
        results.add(advanced);

        if (advanced.isSuccessful()) {
            return new DiscoveryResult(results);
        }
        // direct method
        results.add(discover(DiscoveryMethod.direct, address));

        return new DiscoveryResult(results);
    }

    default DiscoveryResult discoverByEmail(String email) throws MalformedUserIdException {
        return discover(WKDAddress.fromEmail(email));
    }

    default DiscoveryResult discoverByUserId(String userId) throws MalformedUserIdException {
        return discover(WKDAddressHelper.wkdAddressFromUserId(userId));
    }

}
