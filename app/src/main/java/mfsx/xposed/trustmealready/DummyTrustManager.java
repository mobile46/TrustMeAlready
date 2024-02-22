package mfsx.xposed.trustmealready;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

public class DummyTrustManager implements X509TrustManager {
    private static TrustManager[] trustManagers = null;

    public static TrustManager[] getInstance() {
        if (trustManagers == null) {
            trustManagers = new TrustManager[1];
            trustManagers[0] = new DummyTrustManager();
        }
        return trustManagers;
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType) {
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType) {
    }

    @SuppressWarnings("unused")
    public List<X509Certificate> checkServerTrusted(X509Certificate[] chain, String authType, String host) {
        return new ArrayList<>();
    }

    public X509Certificate[] getAcceptedIssuers() {
        return new X509Certificate[0];
    }
}