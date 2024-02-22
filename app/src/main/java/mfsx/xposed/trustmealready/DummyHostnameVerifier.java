package mfsx.xposed.trustmealready;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLSession;

public class DummyHostnameVerifier implements HostnameVerifier {
    @Override
    public boolean verify(String hostname, SSLSession session) {
        return true;
    }
}
