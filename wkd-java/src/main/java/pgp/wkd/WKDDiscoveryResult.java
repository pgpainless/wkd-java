// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package pgp.wkd;

import pgp.certificate_store.Certificate;

import java.util.ArrayList;
import java.util.List;

public class WKDDiscoveryResult {

    private List<WKDDiscoveryItem> items;

    public WKDDiscoveryResult(List<WKDDiscoveryItem> items) {
        this.items = items;
    }

    public List<Certificate> getCertificates() {
        List<Certificate> certificates = new ArrayList<>();

        for (WKDDiscoveryItem item : items) {
            if (item.isSuccessful()) {
                certificates.addAll(item.getCertificates());
            }
        }
        return certificates;
    }

    public boolean isSuccessful() {
        for (WKDDiscoveryItem item : items) {
            if (item.isSuccessful() && item.hasCertificates()) {
                return true;
            }
        }
        return false;
    }

    public List<WKDDiscoveryItem> getItems() {
        return items;
    }

    public List<WKDDiscoveryItem> getFailedItems() {
        List<WKDDiscoveryItem> fails = new ArrayList<>();
        for (WKDDiscoveryItem item : items) {
            if (!item.isSuccessful()) {
                fails.add(item);
            }
        }
        return fails;
    }
}
