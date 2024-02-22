package mfsx.xposed.trustmealready;

import static de.robv.android.xposed.XC_MethodReplacement.DO_NOTHING;
import static de.robv.android.xposed.XC_MethodReplacement.returnConstant;
import static de.robv.android.xposed.XposedHelpers.callMethod;
import static de.robv.android.xposed.XposedHelpers.callStaticMethod;
import static de.robv.android.xposed.XposedHelpers.findAndHookConstructor;
import static de.robv.android.xposed.XposedHelpers.findAndHookMethod;
import static de.robv.android.xposed.XposedHelpers.findClass;
import static de.robv.android.xposed.XposedHelpers.getObjectField;
import static de.robv.android.xposed.XposedHelpers.newInstance;
import static de.robv.android.xposed.XposedHelpers.setObjectField;

import android.annotation.SuppressLint;

import org.apache.http.conn.scheme.HostNameResolver;
import org.apache.http.conn.ssl.SSLSocketFactory;

import java.lang.reflect.Method;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XC_MethodReplacement;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.callbacks.XC_LoadPackage.LoadPackageParam;

public class Main implements IXposedHookLoadPackage {
    String packageName;
    ClassLoader classLoader;

    int hookedMethods = 0;

    public void handleLoadPackage(final LoadPackageParam lpparam) {
        packageName = lpparam.packageName;
        classLoader = lpparam.classLoader;

        XposedBridge.log("TrustMeAlready loading: " + packageName);

        try {
            String className = "com.android.org.conscrypt.TrustManagerImpl";
            String methodName = "checkTrustedRecursive";
            String methodName2 = "checkServerTrusted";
            String methodName3 = "checkTrusted";
            String methodName4 = "verifyChain";
            for (Method method : findClass(className, classLoader).getDeclaredMethods()) {
                String name = method.getName();
                if (methodName.equals(name) || methodName2.equals(name) || methodName3.equals(name)) {
                    List<Object> params = new ArrayList<>(Arrays.asList(method.getParameterTypes()));
                    if (method.getReturnType().equals(void.class)) {
                        params.add(DO_NOTHING);
                    } else {
                        params.add(returnConstant(new ArrayList<X509Certificate>()));
                    }
                    findAndHookMethod(className, classLoader, name, params.toArray());
                    logHookedMethod(method.toString());
                } else if (methodName4.equals(name)) {
                    List<Object> params = new ArrayList<>(Arrays.asList(method.getParameterTypes()));
                    params.add(new XC_MethodReplacement() {
                        @Override
                        protected Object replaceHookedMethod(MethodHookParam param) {
                            return param.args[0];
                        }
                    });
                    findAndHookMethod(className, classLoader, name, params.toArray());
                    logHookedMethod(method.toString());
                }
            }
        } catch (Error e) {
            logError(e);
        }

        try {
            String className = "com.android.org.conscrypt.OpenSSLSocketImpl";
            String methodName = "verifyCertificateChain";
            for (Method method : findClass(className, classLoader).getDeclaredMethods()) {
                String name = method.getName();
                if (methodName.equals(name)) {
                    List<Object> params = new ArrayList<>(Arrays.asList(method.getParameterTypes()));
                    params.add(DO_NOTHING);
                    findAndHookMethod(className, classLoader, name, params.toArray());
                    logHookedMethod(method.toString());
                }
            }
        } catch (Error e) {
            logError(e);
        }

        try {
            String className = "com.android.org.conscrypt.OpenSSLEngineSocketImpl";
            String methodName = "verifyCertificateChain";
            for (Method method : findClass(className, classLoader).getDeclaredMethods()) {
                String name = method.getName();
                if (methodName.equals(name)) {
                    List<Object> params = new ArrayList<>(Arrays.asList(method.getParameterTypes()));
                    params.add(DO_NOTHING);
                    findAndHookMethod(className, classLoader, name, params.toArray());
                    logHookedMethod(method.toString());
                }
            }
        } catch (Error e) {
            logError(e);
        }

        try {
            String className = "com.android.org.conscrypt.ConscryptFileDescriptorSocket";
            String methodName = "verifyCertificateChain";
            for (Method method : findClass(className, classLoader).getDeclaredMethods()) {
                String name = method.getName();
                if (methodName.equals(name)) {
                    List<Object> params = new ArrayList<>(Arrays.asList(method.getParameterTypes()));
                    params.add(DO_NOTHING);
                    findAndHookMethod(className, classLoader, name, params.toArray());
                    logHookedMethod(method.toString());
                }
            }
        } catch (Error e) {
            logError(e);
        }

        try {
            String className = "com.android.org.conscrypt.CertPinManager";
            String methodName = "isChainValid";
            for (Method method : findClass(className, classLoader).getDeclaredMethods()) {
                String name = method.getName();
                if (methodName.equals(name)) {
                    List<Object> params = new ArrayList<>(Arrays.asList(method.getParameterTypes()));
                    params.add(returnConstant(true));
                    findAndHookMethod(className, classLoader, name, params.toArray());
                    logHookedMethod(method.toString());
                }
            }
        } catch (Error e) {
            logError(e);
        }

        try {
            String className = "android.security.net.config.NetworkSecurityTrustManager";
            String methodName = "checkPins";
            for (Method method : findClass(className, classLoader).getDeclaredMethods()) {
                String name = method.getName();
                if (methodName.equals(name)) {
                    List<Object> params = new ArrayList<>(Arrays.asList(method.getParameterTypes()));
                    params.add(DO_NOTHING);
                    findAndHookMethod(className, classLoader, name, params.toArray());
                    logHookedMethod(method.toString());
                }
            }
        } catch (Error e) {
            logError(e);
        }

        try {
            String className = "android.webkit.WebViewClient";
            String methodName = "onReceivedSslError";
            String methodName2 = "onReceivedError";
            for (Method method : findClass(className, classLoader).getDeclaredMethods()) {
                String name = method.getName();
                if (methodName.equals(name)) {
                    List<Object> params = new ArrayList<>(Arrays.asList(method.getParameterTypes()));
                    params.add(new XC_MethodReplacement() {
                        @Override
                        protected Object replaceHookedMethod(MethodHookParam param) {
                            ((android.webkit.SslErrorHandler) param.args[1]).proceed();
                            return null;
                        }
                    });
                    findAndHookMethod(className, classLoader, name, params.toArray());
                    logHookedMethod(method.toString());
                } else if (methodName2.equals(name)) {
                    List<Object> params = new ArrayList<>(Arrays.asList(method.getParameterTypes()));
                    params.add(DO_NOTHING);
                    findAndHookMethod(className, classLoader, name, params.toArray());
                    logHookedMethod(method.toString());
                }
            }
        } catch (Error e) {
            logError(e);
        }

        try {
            String className = "javax.net.ssl.HttpsURLConnection";
            String methodName = "setHostnameVerifier";
            String methodName2 = "setSSLSocketFactory";
            String methodName3 = "setDefaultHostnameVerifier";
            for (Method method : findClass(className, classLoader).getDeclaredMethods()) {
                String name = method.getName();
                if (name.equals(methodName) || name.equals(methodName2) || name.equals(methodName3)) {
                    List<Object> params = new ArrayList<>(Arrays.asList(method.getParameterTypes()));
                    params.add(DO_NOTHING);
                    findAndHookMethod(className, classLoader, name, params.toArray());
                    logHookedMethod(method.toString());
                }
            }
        } catch (Error e) {
            logError(e);
        }

        try {
            String className = "javax.net.ssl.SSLContext";
            String methodName = "init";
            for (Method method : findClass(className, classLoader).getDeclaredMethods()) {
                String name = method.getName();
                if (methodName.equals(name)) {
                    List<Object> params = new ArrayList<>(Arrays.asList(method.getParameterTypes()));
                    params.add(new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param) {
                            param.args[0] = null;
                            param.args[1] = DummyTrustManager.getInstance();
                            param.args[2] = null;
                        }
                    });
                    findAndHookMethod(className, classLoader, name, params.toArray());
                    logHookedMethod(method.toString());
                }
            }
        } catch (Error e) {
            logError(e);
        }

        try {
            String className = "javax.net.ssl.TrustManagerFactory";
            String className2 = "com.android.org.conscrypt.TrustManagerImpl";
            String methodName = "getTrustManagers";
            for (Method method : findClass(className, classLoader).getDeclaredMethods()) {
                String name = method.getName();
                if (methodName.equals(name)) {
                    List<Object> params = new ArrayList<>(Arrays.asList(method.getParameterTypes()));
                    params.add(new XC_MethodHook() {
                        @SuppressLint("PrivateApi")
                        @Override
                        protected void afterHookedMethod(MethodHookParam param) {
                            try {
                                Class.forName(className2);
                                Class<?> clazz = findClass(className2, classLoader);
                                TrustManager[] trustManagers = (TrustManager[]) param.getResult();
                                if (trustManagers.length > 0 && clazz.isInstance(trustManagers[0]))
                                    return;
                            } catch (ClassNotFoundException ignored) {
                                return;
                            }
                            param.setResult(DummyTrustManager.getInstance());
                        }
                    });
                    findAndHookMethod(className, classLoader, name, params.toArray());
                    logHookedMethod(method.toString());
                }
            }
        } catch (Error e) {
            logError(e);
        }

        try {
            String className = "org.apache.http.conn.scheme.SchemeRegistry";
            String methodName = "register";
            for (Method method : findClass(className, classLoader).getDeclaredMethods()) {
                String name = method.getName();
                if (methodName.equals(name)) {
                    List<Object> params = new ArrayList<>(Arrays.asList(method.getParameterTypes()));
                    params.add(new XC_MethodHook() {
                        protected void beforeHookedMethod(XC_MethodHook.MethodHookParam param) {
                            Object obj = param.args[0];
                            if (callMethod(obj, "getName") == "https") {
                                param.args[0] = newInstance(obj.getClass(), "https", SSLSocketFactory.getSocketFactory(), 443);
                            }
                        }
                    });
                    findAndHookMethod(className, classLoader, name, params.toArray());
                    logHookedMethod(method.toString());
                }
            }
        } catch (Error e) {
            logError(e);
        }

        try {
            String className = "org.apache.http.conn.ssl.HttpsURLConnection";
            String methodName = "setDefaultHostnameVerifier";
            String methodName2 = "setHostnameVerifier";
            for (Method method : findClass(className, classLoader).getDeclaredMethods()) {
                String name = method.getName();
                if (methodName.equals(name) || methodName2.equals(name)) {
                    List<Object> params = new ArrayList<>(Arrays.asList(method.getParameterTypes()));
                    params.add(new XC_MethodHook() {
                        protected void beforeHookedMethod(XC_MethodHook.MethodHookParam param) {
                            param.args[0] = org.apache.http.conn.ssl.SSLSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER;
                        }
                    });
                    findAndHookMethod(className, classLoader, name, params.toArray());
                    logHookedMethod(method.toString());
                }
            }
        } catch (Error e) {
            logError(e);
        }

        try {
            String className = "org.apache.http.conn.ssl.SSLSocketFactory";
            String methodName = "getSocketFactory";
            String methodName2 = "isSecure";
            for (Method method : findClass(className, classLoader).getDeclaredMethods()) {
                String name = method.getName();
                if (methodName.equals(name)) {
                    List<Object> params = new ArrayList<>(Arrays.asList(method.getParameterTypes()));
                    params.add(new XC_MethodHook() {
                        protected void beforeHookedMethod(XC_MethodHook.MethodHookParam param) {
                            param.setResult(newInstance(org.apache.http.conn.ssl.SSLSocketFactory.class));
                        }
                    });
                    findAndHookMethod(className, classLoader, name, params.toArray());
                    logHookedMethod(method.toString());
                } else if (methodName2.equals(name)) {
                    List<Object> params = new ArrayList<>(Arrays.asList(method.getParameterTypes()));
                    params.add(new XC_MethodHook() {
                        protected void beforeHookedMethod(MethodHookParam param) {
                            param.setResult(true);
                        }
                    });
                    findAndHookMethod(className, classLoader, name, params.toArray());
                    logHookedMethod(method.toString());
                }
            }
        } catch (Error e) {
            logError(e);
        }

        try {
            String className = "org.apache.http.conn.ssl.SSLSocketFactory";
            Class<?> sslSocketFactory = findClass(className, classLoader);
            findAndHookConstructor(sslSocketFactory, String.class, KeyStore.class, String.class, KeyStore.class, SecureRandom.class, HostNameResolver.class, new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    String algorithm = (String) param.args[0];
                    KeyStore keystore = (KeyStore) param.args[1];
                    String keystorePassword = (String) param.args[2];
                    SecureRandom random = (SecureRandom) param.args[4];

                    KeyManager[] keymanagers = null;

                    if (keystore != null) {
                        keymanagers = (KeyManager[]) callStaticMethod(SSLSocketFactory.class, "createKeyManagers", keystore, keystorePassword);
                    }

                    TrustManager[] trustmanagers = DummyTrustManager.getInstance();

                    setObjectField(param.thisObject, "sslcontext", SSLContext.getInstance(algorithm));
                    callMethod(getObjectField(param.thisObject, "sslcontext"), "init", keymanagers, trustmanagers, random);
                    setObjectField(param.thisObject, "socketfactory", callMethod(getObjectField(param.thisObject, "sslcontext"), "getSocketFactory"));
                }
            });
            logHookedMethod(className);
        } catch (Error e) {
            logError(e);
        }

        try {
            String className = "okhttp3.CertificatePinner";
            String methodName = "findMatchingPins";
            String methodName2 = "check";
            String methodName3 = "check$okhttp";
            for (Method method : findClass(className, classLoader).getDeclaredMethods()) {
                String name = method.getName();
                if (methodName.equals(name)) {
                    List<Object> params = new ArrayList<>(Arrays.asList(method.getParameterTypes()));
                    params.add(new XC_MethodHook() {
                        protected void beforeHookedMethod(XC_MethodHook.MethodHookParam param) {
                            param.args[0] = "";
                        }
                    });
                    findAndHookMethod(className, classLoader, name, params.toArray());
                    logHookedMethod(method.toString());
                } else if (methodName2.equals(name) || methodName3.equals(name)) {
                    List<Object> params = new ArrayList<>(Arrays.asList(method.getParameterTypes()));
                    params.add(DO_NOTHING);
                    findAndHookMethod(className, classLoader, name, params.toArray());
                    logHookedMethod(method.toString());
                }
            }
        } catch (Error e) {
            logError(e);
        }

        try {
            String className = "okhttp3.repackaged.CertificatePinner";
            String methodName = "findMatchingPins";
            String methodName2 = "check";
            String methodName3 = "check$okhttp";
            for (Method method : findClass(className, classLoader).getDeclaredMethods()) {
                String name = method.getName();
                if (methodName.equals(name)) {
                    List<Object> params = new ArrayList<>(Arrays.asList(method.getParameterTypes()));
                    params.add(new XC_MethodHook() {
                        protected void beforeHookedMethod(XC_MethodHook.MethodHookParam param) {
                            param.args[0] = "";
                        }
                    });
                    findAndHookMethod(className, classLoader, name, params.toArray());
                    logHookedMethod(method.toString());
                } else if (methodName2.equals(name) || methodName3.equals(name)) {
                    List<Object> params = new ArrayList<>(Arrays.asList(method.getParameterTypes()));
                    params.add(DO_NOTHING);
                    findAndHookMethod(className, classLoader, name, params.toArray());
                    logHookedMethod(method.toString());
                }
            }
        } catch (Error e) {
            logError(e);
        }

        try {
            String className = "com.commencis.okhttp3.CertificatePinner";
            String methodName = "check";
            String methodName2 = "check$okhttp";
            for (Method method : findClass(className, classLoader).getDeclaredMethods()) {
                String name = method.getName();
                if (methodName.equals(name) || methodName2.equals(name)) {
                    List<Object> params = new ArrayList<>(Arrays.asList(method.getParameterTypes()));
                    params.add(DO_NOTHING);
                    findAndHookMethod(className, classLoader, name, params.toArray());
                    logHookedMethod(method.toString());
                }
            }
        } catch (Error e) {
            logError(e);
        }

        try {
            String className = "okhttp3.internal.tls.OkHostnameVerifier";
            String methodName = "verify";
            for (Method method : findClass(className, classLoader).getDeclaredMethods()) {
                String name = method.getName();
                if (methodName.equals(name)) {
                    List<Object> params = new ArrayList<>(Arrays.asList(method.getParameterTypes()));
                    params.add(returnConstant(true));
                    findAndHookMethod(className, classLoader, name, params.toArray());
                    logHookedMethod(method.toString());
                }
            }
        } catch (Error e) {
            logError(e);
        }

        try {
            String className = "com.squareup.okhttp.CertificatePinner";
            String methodName = "check";
            for (Method method : findClass(className, classLoader).getDeclaredMethods()) {
                String name = method.getName();
                if (methodName.equals(name)) {
                    List<Object> params = new ArrayList<>(Arrays.asList(method.getParameterTypes()));
                    params.add(DO_NOTHING);
                    findAndHookMethod(className, classLoader, name, params.toArray());
                    logHookedMethod(method.toString());
                }
            }
        } catch (Error e) {
            logError(e);
        }

        try {
            String className = "com.squareup.okhttp.internal.tls.OkHostnameVerifier";
            String methodName = "verify";
            for (Method method : findClass(className, classLoader).getDeclaredMethods()) {
                String name = method.getName();
                if (methodName.equals(name)) {
                    List<Object> params = new ArrayList<>(Arrays.asList(method.getParameterTypes()));
                    params.add(returnConstant(true));
                    findAndHookMethod(className, classLoader, name, params.toArray());
                    logHookedMethod(method.toString());
                }
            }
        } catch (Error e) {
            logError(e);
        }

        try {
            String className = "org.xutils.http.RequestParams";
            String methodName = "setSslSocketFactory";
            String methodName2 = "setHostnameVerifier";
            for (Method method : findClass(className, classLoader).getDeclaredMethods()) {
                String name = method.getName();
                if (methodName.equals(name)) {
                    List<Object> params = new ArrayList<>(Arrays.asList(method.getParameterTypes()));
                    params.add(new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param) {
                            param.args[0] = DummySSLSocketFactory.createDefault();
                        }
                    });
                    findAndHookMethod(className, classLoader, name, params.toArray());
                    logHookedMethod(method.toString());
                } else if (methodName2.equals(name)) {
                    List<Object> params = new ArrayList<>(Arrays.asList(method.getParameterTypes()));
                    params.add(new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param) {
                            param.args[0] = new DummyHostnameVerifier();
                        }
                    });
                    findAndHookMethod(className, classLoader, name, params.toArray());
                    logHookedMethod(method.toString());
                }
            }
        } catch (Error e) {
            logError(e);
        }

        try {
            String className = "com.appmattus.certificatetransparency.internal.verifier.CertificateTransparencyInterceptor";
            String methodName = "intercept";
            for (Method method : findClass(className, classLoader).getDeclaredMethods()) {
                String name = method.getName();
                if (methodName.equals(name)) {
                    List<Object> params = new ArrayList<>(Arrays.asList(method.getParameterTypes()));
                    params.add(new XC_MethodReplacement() {
                        @Override
                        protected Object replaceHookedMethod(MethodHookParam param) {
                            Object chain = param.args[0];
                            Object request = callMethod(chain, "request");
                            return callMethod(chain, "proceed", request);
                        }
                    });
                    findAndHookMethod(className, classLoader, name, params.toArray());
                    logHookedMethod(method.toString());
                }
            }
        } catch (Error e) {
            logError(e);
        }

        try {
            String className = "com.appmattus.certificatetransparency.internal.verifier.CertificateTransparencyTrustManager";
            String methodName = "checkServerTrusted";
            for (Method method : findClass(className, classLoader).getDeclaredMethods()) {
                String name = method.getName();
                if (methodName.equals(name)) {
                    List<Object> params = new ArrayList<>(Arrays.asList(method.getParameterTypes()));
                    if (method.getReturnType().equals(void.class)) {
                        params.add(DO_NOTHING);
                    } else {
                        params.add(returnConstant(new ArrayList<X509Certificate>()));
                    }
                    findAndHookMethod(className, classLoader, name, params.toArray());
                    logHookedMethod(method.toString());
                }
            }
        } catch (Error e) {
            logError(e);
        }

        try {
            String className = "appcelerator.https.PinningTrustManager";
            String methodName = "checkServerTrusted";
            for (Method method : findClass(className, classLoader).getDeclaredMethods()) {
                String name = method.getName();
                if (methodName.equals(name)) {
                    List<Object> params = new ArrayList<>(Arrays.asList(method.getParameterTypes()));
                    params.add(DO_NOTHING);
                    findAndHookMethod(className, classLoader, name, params.toArray());
                    logHookedMethod(method.toString());
                }
            }
        } catch (Error e) {
            logError(e);
        }

        try {
            String className = "ch.boye.httpclientandroidlib.conn.ssl.AbstractVerifier";
            String methodName = "verify";
            for (Method method : findClass(className, classLoader).getDeclaredMethods()) {
                String name = method.getName();
                if (methodName.equals(name)) {
                    List<Object> params = new ArrayList<>(Arrays.asList(method.getParameterTypes()));
                    params.add(DO_NOTHING);
                    findAndHookMethod(className, classLoader, name, params.toArray());
                    logHookedMethod(method.toString());
                }
            }
        } catch (Error e) {
            logError(e);
        }

        try {
            String className = "org.chromium.net.CronetEngine$Builder";
            String methodName = "enablePublicKeyPinningBypassForLocalTrustAnchors";
            String methodName2 = "addPublicKeyPins";
            for (Method method : findClass(className, classLoader).getDeclaredMethods()) {
                String name = method.getName();
                if (methodName.equals(name)) {
                    List<Object> params = new ArrayList<>(Arrays.asList(method.getParameterTypes()));
                    params.add(new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param) {
                            param.args[0] = true;
                        }
                    });
                    findAndHookMethod(className, classLoader, name, params.toArray());
                    logHookedMethod(method.toString());
                } else if (methodName2.equals(name)) {
                    List<Object> params = new ArrayList<>(Arrays.asList(method.getParameterTypes()));
                    params.add(new XC_MethodReplacement() {
                        @Override
                        protected Object replaceHookedMethod(MethodHookParam param) {
                            return param.thisObject;
                        }
                    });
                    findAndHookMethod(className, classLoader, name, params.toArray());
                    logHookedMethod(method.toString());
                }
            }
        } catch (Error e) {
            logError(e);
        }

        try {
            String className = "com.datatheorem.android.trustkit.pinning.OkHostnameVerifier";
            String methodName = "verify";
            for (Method method : findClass(className, classLoader).getDeclaredMethods()) {
                String name = method.getName();
                if (methodName.equals(name)) {
                    List<Object> params = new ArrayList<>(Arrays.asList(method.getParameterTypes()));
                    params.add(returnConstant(true));
                    findAndHookMethod(className, classLoader, name, params.toArray());
                    logHookedMethod(method.toString());
                }
            }
        } catch (Error e) {
            logError(e);
        }

        try {
            String className = "com.datatheorem.android.trustkit.pinning.PinningTrustManager";
            String methodName = "checkServerTrusted";
            for (Method method : findClass(className, classLoader).getDeclaredMethods()) {
                String name = method.getName();
                if (methodName.equals(name)) {
                    List<Object> params = new ArrayList<>(Arrays.asList(method.getParameterTypes()));
                    params.add(DO_NOTHING);
                    findAndHookMethod(className, classLoader, name, params.toArray());
                    logHookedMethod(method.toString());
                }
            }
        } catch (Error e) {
            logError(e);
        }

        try {
            String className = "com.commonsware.cwac.netsecurity.conscrypt.CertPinManager";
            String methodName = "isChainValid";
            for (Method method : findClass(className, classLoader).getDeclaredMethods()) {
                String name = method.getName();
                if (methodName.equals(name)) {
                    List<Object> params = new ArrayList<>(Arrays.asList(method.getParameterTypes()));
                    params.add(returnConstant(true));
                    findAndHookMethod(className, classLoader, name, params.toArray());
                    logHookedMethod(method.toString());
                }
            }
        } catch (Error e) {
            logError(e);
        }

        try {
            String className = "com.worklight.wlclient.certificatepinning.HostNameVerifierWithCertificatePinning";
            String methodName = "verify";
            for (Method method : findClass(className, classLoader).getDeclaredMethods()) {
                String name = method.getName();
                if (methodName.equals(name)) {
                    List<Object> params = new ArrayList<>(Arrays.asList(method.getParameterTypes()));
                    params.add(DO_NOTHING);
                    findAndHookMethod(className, classLoader, name, params.toArray());
                    logHookedMethod(method.toString());
                }
            }
        } catch (Error e) {
            logError(e);
        }

        try {
            String className = "com.worklight.wlclient.api.WLClient";
            String methodName = "pinTrustedCertificatePublicKey";
            for (Method method : findClass(className, classLoader).getDeclaredMethods()) {
                String name = method.getName();
                if (methodName.equals(name)) {
                    List<Object> params = new ArrayList<>(Arrays.asList(method.getParameterTypes()));
                    params.add(DO_NOTHING);
                    findAndHookMethod(className, classLoader, name, params.toArray());
                    logHookedMethod(method.toString());
                }
            }
        } catch (Error e) {
            logError(e);
        }

        try {
            String className = "com.worklight.androidgap.plugin.WLCertificatePinningPlugin";
            String methodName = "execute";
            for (Method method : findClass(className, classLoader).getDeclaredMethods()) {
                String name = method.getName();
                if (methodName.equals(name)) {
                    List<Object> params = new ArrayList<>(Arrays.asList(method.getParameterTypes()));
                    params.add(returnConstant(true));
                    findAndHookMethod(className, classLoader, name, params.toArray());
                    logHookedMethod(method.toString());
                }
            }
        } catch (Error e) {
            logError(e);
        }

        try {
            String className = "nl.xservices.plugins.sslCertificateChecker";
            String methodName = "execute";
            for (Method method : findClass(className, classLoader).getDeclaredMethods()) {
                String name = method.getName();
                if (methodName.equals(name)) {
                    List<Object> params = new ArrayList<>(Arrays.asList(method.getParameterTypes()));
                    params.add(returnConstant(true));
                    findAndHookMethod(className, classLoader, name, params.toArray());
                    logHookedMethod(method.toString());
                }
            }
        } catch (Error e) {
            logError(e);
        }

        try {
            String className = "io.netty.handler.ssl.util.FingerprintTrustManagerFactory";
            String methodName = "checkTrusted";
            for (Method method : findClass(className, classLoader).getDeclaredMethods()) {
                String name = method.getName();
                if (methodName.equals(name)) {
                    List<Object> params = new ArrayList<>(Arrays.asList(method.getParameterTypes()));
                    params.add(DO_NOTHING);
                    findAndHookMethod(className, classLoader, name, params.toArray());
                    logHookedMethod(method.toString());
                }
            }
        } catch (Error e) {
            logError(e);
        }

        try {
            String className = "org.apache.cordova.CordovaWebViewClient";
            String methodName = "onReceivedSslError";
            for (Method method : findClass(className, classLoader).getDeclaredMethods()) {
                String name = method.getName();
                if (methodName.equals(name)) {
                    List<Object> params = new ArrayList<>(Arrays.asList(method.getParameterTypes()));
                    params.add(new XC_MethodReplacement() {
                        @Override
                        protected Object replaceHookedMethod(MethodHookParam param) {
                            ((android.webkit.SslErrorHandler) param.args[2]).proceed();
                            return null;
                        }
                    });
                    findAndHookMethod(className, classLoader, name, params.toArray());
                    logHookedMethod(method.toString());
                }
            }
        } catch (Error e) {
            logError(e);
        }

        try {
            String className = "org.apache.harmony.xnet.provider.jsse.OpenSSLSocketImpl";
            String methodName = "verifyCertificateChain";
            for (Method method : findClass(className, classLoader).getDeclaredMethods()) {
                String name = method.getName();
                if (methodName.equals(name)) {
                    List<Object> params = new ArrayList<>(Arrays.asList(method.getParameterTypes()));
                    params.add(DO_NOTHING);
                    findAndHookMethod(className, classLoader, name, params.toArray());
                    logHookedMethod(method.toString());
                }
            }
        } catch (Error e) {
            logError(e);
        }

        try {
            String className = "com.turkcell.paycell.data.DataModule";
            String methodName = "checkCertificate";
            for (Method method : findClass(className, classLoader).getDeclaredMethods()) {
                String name = method.getName();
                if (methodName.equals(name)) {
                    List<Object> params = new ArrayList<>(Arrays.asList(method.getParameterTypes()));
                    params.add(returnConstant(true));
                    findAndHookMethod(className, classLoader, name, params.toArray());
                    logHookedMethod(method.toString());
                }
            }
        } catch (Error e) {
            logError(e);
        }

        XposedBridge.log("TrustMeAlready loaded! Hooked " + hookedMethods + " methods");
    }

    private void logHookedMethod(String text) {
        XposedBridge.log("Hooked method: " + text);
        hookedMethods++;
    }

    private void logError(Error e) {
        XposedBridge.log("Hooking error: " + e.getMessage());
    }
}

