// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package pgp.wkd.discovery;

import pgp.certificate_store.Certificate;

import javax.annotation.Nonnull;
import java.util.ArrayList;
import java.util.List;

public class DiscoveryResult {

    private List<DiscoveryResponse> items;

    public DiscoveryResult(@Nonnull List<DiscoveryResponse> items) {
        this.items = items;
    }

    @Nonnull
    public List<Certificate> getCertificates() {
        List<Certificate> certificates = new ArrayList<>();

        for (DiscoveryResponse item : items) {
            if (item.isSuccessful()) {
                certificates.addAll(item.getCertificates());
            }
        }
        return certificates;
    }

    public boolean isSuccessful() {
        for (DiscoveryResponse item : items) {
            if (item.isSuccessful() && item.hasCertificates()) {
                return true;
            }
        }
        return false;
    }

    @Nonnull
    public List<DiscoveryResponse> getItems() {
        return items;
    }

    @Nonnull
    public List<DiscoveryResponse> getFailedItems() {
        List<DiscoveryResponse> fails = new ArrayList<>();
        for (DiscoveryResponse item : items) {
            if (!item.isSuccessful()) {
                fails.add(item);
            }
        }
        return fails;
    }
}
