// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package pgp.wkd;

import java.util.ArrayList;
import java.util.List;

public interface Discover {

    WKDDiscoveryItem discover(DiscoveryMethod method, WKDAddress address);

    default WKDDiscoveryResult discover(WKDAddress address) {
        List<WKDDiscoveryItem> results = new ArrayList<>();

        // advanced method
        WKDDiscoveryItem advanced = discover(DiscoveryMethod.advanced, address);
        results.add(advanced);

        if (advanced.isSuccessful()) {
            return new WKDDiscoveryResult(results);
        }
        // direct method
        results.add(discover(DiscoveryMethod.direct, address));

        return new WKDDiscoveryResult(results);
    }

    default WKDDiscoveryResult discoverByEmail(String email) throws MalformedUserIdException {
        return discover(WKDAddress.fromEmail(email));
    }

    default WKDDiscoveryResult discoverByUserId(String userId) throws MalformedUserIdException {
        return discover(WKDAddressHelper.wkdAddressFromUserId(userId));
    }

}
