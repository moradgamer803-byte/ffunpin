package com.zyvo.ffunpin;

import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.os.Build;
import android.util.Log;

import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

/**
 * FFUnpin — TLS unpinning for Free Fire on the user's OWN device.
 * Two layers:
 *   1. Java: replace TrustManager / OkHttp pinner / hostname verifier.
 *   2. Native: GOT-patch OpenSSL-BoringSSL verify functions inside the game
 *      process (UnityWebRequest + libcurl use these, not the Java stack).
 */
public class FFHook implements IXposedHookLoadPackage {

    private static final String TAG = "FFUnpin";
    private static final String MODULE_PKG = "com.zyvo.ffunpin";

    private static final X509TrustManager TRUST_ALL = new X509TrustManager() {
        @Override public void checkClientTrusted(X509Certificate[] chain, String authType) { }
        @Override public void checkServerTrusted(X509Certificate[] chain, String authType) { }
        @Override public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
    };

    private static void log(String s) {
        Log.i(TAG, s);
        try { XposedBridge.log(TAG + ": " + s); } catch (Throwable ignored) { }
    }

    @Override
    public void handleLoadPackage(XC_LoadPackage.LoadPackageParam lpparam) {
        String p = lpparam.packageName;
        if (p == null) return;
        if (!p.equals("com.dts.freefireth") && !p.equals("com.dts.freefiremax")) return;

        log("scoped: " + p + " proc=" + lpparam.processName);
        hookJavaTls();
        try { loadNative(lpparam); }
        catch (Throwable t) { log("native load failed: " + t); }
    }

    // ---------------------------------------------------------------- native

    private void loadNative(XC_LoadPackage.LoadPackageParam lpparam) throws Exception {
        if (!"arm64-v8a".equals(Build.SUPPORTED_ABIS[0])) {
            log("abi " + Build.SUPPORTED_ABIS[0] + " not patched (arm64 only)");
            return;
        }
        String moduleApk = moduleApkPath(lpparam);
        if (moduleApk == null) { log("module apk path not found"); return; }

        File outDir = new File(lpparam.appInfo.dataDir, "ffunpin");
        if (!outDir.exists() && !outDir.mkdirs()) { log("cannot mkdir " + outDir); return; }
        File so = new File(outDir, "libffunpin.so");

        try (ZipFile zip = new ZipFile(moduleApk)) {
            ZipEntry e = zip.getEntry("lib/arm64-v8a/libffunpin.so");
            if (e == null) { log("lib missing in module apk"); return; }
            try (InputStream in = zip.getInputStream(e);
                 FileOutputStream fos = new FileOutputStream(so)) {
                byte[] buf = new byte[8192];
                int n;
                while ((n = in.read(buf)) > 0) fos.write(buf, 0, n);
            }
        }
        so.setReadable(true, false);
        so.setExecutable(true, false);
        System.load(so.getAbsolutePath());
        log("native loaded: " + so + " (" + so.length() + "B)");
    }

    private String moduleApkPath(XC_LoadPackage.LoadPackageParam lpparam) {
        try {
            Class<?> at = Class.forName("android.app.ActivityThread");
            Object thread = at.getMethod("currentActivityThread").invoke(null);
            Context ctx = null;
            if (thread != null) {
                Object sys = XposedHelpers.callMethod(thread, "getSystemContext");
                if (sys instanceof Context) ctx = (Context) sys;
            }
            if (ctx == null) ctx = (Context) XposedHelpers.getStaticObjectField(at, "mInitialApplication");
            if (ctx == null) return null;
            ApplicationInfo ai = ctx.getPackageManager().getApplicationInfo(MODULE_PKG, 0);
            return ai.sourceDir;
        } catch (Throwable t) {
            log("moduleApkPath: " + t);
        }
        // fallback: some LSPosed builds put the module apk in the classpath
        try {
            java.security.CodeSource cs = FFHook.class.getProtectionDomain().getCodeSource();
            if (cs != null && cs.getLocation() != null) return new File(cs.getLocation().toURI()).getAbsolutePath();
        } catch (Throwable ignored) { }
        return null;
    }

    // ------------------------------------------------------------------ java

    private void hookJavaTls() {
        // 1. every SSLContext created by the app gets an accept-all TrustManager
        try {
            XposedBridge.hookAllMethods(SSLContext.class, "init", new XC_MethodHook() {
                @Override protected void beforeHookedMethod(MethodHookParam param) {
                    if (param.args.length >= 2) {
                        param.args[1] = new TrustManager[]{TRUST_ALL};
                        log("SSLContext.init -> trust-all");
                    }
                }
            });
        } catch (Throwable t) { log("hook SSLContext.init: " + t); }

        // 2. Conscrypt internals (default provider path)
        hookAll("com.android.org.conscrypt.TrustManagerImpl", "checkTrustedRecursive",
                new XC_MethodHook() {
                    @Override protected void afterHookedMethod(MethodHookParam param) {
                        param.setResult(new ArrayList<X509Certificate>());
                    }
                });
        hookAll("com.android.org.conscrypt.TrustManagerImpl", "checkServerTrusted",
                new XC_MethodHook() {
                    @Override protected void beforeHookedMethod(MethodHookParam param) {
                        param.setResult(null);
                    }
                });
        hookAll("com.android.org.conscrypt.TrustManagerImpl", "verifyChain",
                new XC_MethodHook() {
                    @Override protected void afterHookedMethod(MethodHookParam param) {
                        param.setResult(null);
                    }
                });

        // 3. OkHttp pinner (Garena SDK / Firebase use okhttp)
        hookAll("okhttp3.CertificatePinner", "check", noopHook());
        hookAll("okhttp3.CertificatePinner", "check$okhttp", noopHook());
        hookAll("okhttp3.internal.tls.OkHostnameVerifier", "verify",
                new XC_MethodHook() {
                    @Override protected void beforeHookedMethod(MethodHookParam param) {
                        param.setResult(Boolean.TRUE);
                    }
                });

        // 4. trust-all default hostname verifier
        try {
            XposedHelpers.findAndHookMethod(javax.net.ssl.HttpsURLConnection.class,
                    "setDefaultHostnameVerifier", javax.net.ssl.HostnameVerifier.class,
                    new XC_MethodHook() {
                        @Override protected void beforeHookedMethod(MethodHookParam param) {
                            param.args[0] = ALWAYS_TRUE;
                        }
                    });
        } catch (Throwable t) { log("hook setDefaultHostnameVerifier: " + t); }
        log("java hooks armed");
    }

    private static final javax.net.ssl.HostnameVerifier ALWAYS_TRUE = (h, s) -> true;

    private static XC_MethodHook noopHook() {
        return new XC_MethodHook() {
            @Override protected void beforeHookedMethod(MethodHookParam param) { param.setResult(null); }
        };
    }

    private static void hookAll(String cls, String method, XC_MethodHook cb) {
        try {
            Class<?> c = Class.forName(cls);
            XposedBridge.hookAllMethods(c, method, cb);
            log("hook " + cls + "." + method);
        } catch (Throwable t) {
            log("skip " + cls + "." + method + " (" + t.getClass().getSimpleName() + ")");
        }
    }
}
