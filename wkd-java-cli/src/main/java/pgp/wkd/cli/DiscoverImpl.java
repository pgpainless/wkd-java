package pgp.wkd.cli;

import pgp.wkd.AbstractDiscover;
import pgp.wkd.CertificateReader;
import pgp.wkd.HttpUrlConnectionWKDFetcher;
import pgp.wkd.WKDFetcher;

public class DiscoverImpl extends AbstractDiscover {

    public DiscoverImpl() {
        super(new CertificateReaderImpl(), new HttpUrlConnectionWKDFetcher());
    }

    public DiscoverImpl(WKDFetcher fetcher) {
        super(new CertificateReaderImpl(), fetcher);
    }

    public DiscoverImpl(CertificateReader certificateReader, WKDFetcher fetcher) {
        super(certificateReader, fetcher);
    }
}
