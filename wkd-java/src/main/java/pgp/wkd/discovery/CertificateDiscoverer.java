// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package pgp.wkd.discovery;

import pgp.wkd.exception.MalformedUserIdException;
import pgp.wkd.WKDAddress;
import pgp.wkd.WKDAddressHelper;

import java.util.ArrayList;
import java.util.List;

/**
 * Interface which describes an API to discover OpenPGP certificates via the WKD.
 */
public interface CertificateDiscoverer {

    /**
     * Discover OpenPGP certificates by querying the given <pre>address</pre> via the given <pre>method</pre>.
     *
     * @param method discovery method
     * @param address wkd address
     * @return response
     */
    DiscoveryResponse discover(DiscoveryMethod method, WKDAddress address);

    /**
     * Discover OpenPGP certificates by {@link WKDAddress}.
     *
     * @param address address
     * @return discovery result
     */
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

    /**
     * Discover OpenPGP certificates by email address.
     *
     * @param email email address
     * @return discovery result
     *
     * @throws MalformedUserIdException in case of a malformed email address
     */
    default DiscoveryResult discoverByEmail(String email) throws MalformedUserIdException {
        return discover(WKDAddress.fromEmail(email));
    }

    /**
     * Discover OpenPGP certificates by user-id.
     *
     * @param userId user-id
     * @return discovery result
     *
     * @throws MalformedUserIdException in case of a malformed user-id
     */
    default DiscoveryResult discoverByUserId(String userId) throws MalformedUserIdException {
        return discover(WKDAddressHelper.wkdAddressFromUserId(userId));
    }

}
