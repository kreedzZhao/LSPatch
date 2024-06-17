package org.lsposed.lspatch.metaloader;

import android.annotation.SuppressLint;
import android.app.AppComponentFactory;
import android.content.pm.ApplicationInfo;
import android.content.pm.IPackageManager;
import android.os.Build;
import android.os.Process;
import android.os.ServiceManager;
import android.util.JsonReader;
import android.util.Log;

import org.lsposed.hiddenapibypass.HiddenApiBypass;
import org.lsposed.lspatch.share.Constants;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.zip.ZipFile;

@SuppressLint("UnsafeDynamicallyLoadedCode")
public class LSPAppComponentFactoryStub extends AppComponentFactory {

    private static final String TAG = "LSPatch-MetaLoader";
    private static final Map<String, String> archToLib = new HashMap<String, String>(4);

    public static byte[] dex;

    /*
    其实做了两件事，load loaddex 和 load so
     */
    static {
        try {
            // Mapping between architecture names and their corresponding library names
            archToLib.put("arm", "armeabi-v7a");
            archToLib.put("arm64", "arm64-v8a");
            archToLib.put("x86", "x86");
            archToLib.put("x86_64", "x86_64");

            // Get the class loader for the current class
            var cl = Objects.requireNonNull(LSPAppComponentFactoryStub.class.getClassLoader());

            // Reflection to access VMRuntime class and its methods
            Class<?> VMRuntime = Class.forName("dalvik.system.VMRuntime");
            Method getRuntime = VMRuntime.getDeclaredMethod("getRuntime");
            getRuntime.setAccessible(true);
            Method vmInstructionSet = VMRuntime.getDeclaredMethod("vmInstructionSet");
            vmInstructionSet.setAccessible(true);

            // Get the architecture of the current VM
            String arch = (String) vmInstructionSet.invoke(getRuntime.invoke(null));

            /*
             * 获取当前架构
             * VMRuntime vmRuntime = VMRuntime.getRuntime();
             * String vmInstructionSet = vmRuntime.vmInstructionSet();
             */

            // Get the corresponding library name for the architecture
            String libName = archToLib.get(arch);

            boolean useManager = false;
            String soPath;

            // Read the configuration file
            try (var is = cl.getResourceAsStream(Constants.CONFIG_ASSET_PATH);
                 var reader = new JsonReader(new InputStreamReader(is))) {
                reader.beginObject();
                while (reader.hasNext()) {
                    var name = reader.nextName();
                    if (name.equals("useManager")) {
                        // If the configuration file has "useManager", set useManager to its value
                        useManager = reader.nextBoolean();
                        break;
                    } else {
                        reader.skipValue();
                    }
                }
            }

            // If useManager is true, load the library from the manager
            if (useManager) {
                Log.i(TAG, "Bootstrap loader from manager");
                var ipm = IPackageManager.Stub.asInterface(ServiceManager.getService("package"));
                ApplicationInfo manager;
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                    manager = (ApplicationInfo) HiddenApiBypass.invoke(IPackageManager.class, ipm, "getApplicationInfo", Constants.MANAGER_PACKAGE_NAME, 0L, Process.myUid() / 100000);
                } else {
                    manager = ipm.getApplicationInfo(Constants.MANAGER_PACKAGE_NAME, 0, Process.myUid() / 100000);
                }
                // Load the dex file from the manager
                try (var zip = new ZipFile(new File(manager.sourceDir));
                     var is = zip.getInputStream(zip.getEntry(Constants.LOADER_DEX_ASSET_PATH));
                     var os = new ByteArrayOutputStream()) {
                    transfer(is, os);
                    dex = os.toByteArray();
                }
                // Construct the path to the library file
                soPath = manager.sourceDir + "!/assets/lspatch/so/" + libName + "/liblspatch.so";
            } else {
                // If useManager is false, load the library from the embedment
                Log.i(TAG, "Bootstrap loader from embedment");
                try (var is = cl.getResourceAsStream(Constants.LOADER_DEX_ASSET_PATH);
                     var os = new ByteArrayOutputStream()) {
                    transfer(is, os);
                    dex = os.toByteArray();
                }
                // Construct the path to the library file
                soPath = cl.getResource("assets/lspatch/so/" + libName + "/liblspatch.so").getPath().substring(5);
            }

            // dex 是静态类变量，只 load so，所以猜测 so 中肯定有 JNI_OnLoad 方法
            System.load(soPath);
        } catch (Throwable e) {
            // If any error occurs during the initialization, throw an ExceptionInInitializerError
            throw new ExceptionInInitializerError(e);
        }
    }

    private static void transfer(InputStream is, OutputStream os) throws IOException {
        byte[] buffer = new byte[8192];
        int n;
        while (-1 != (n = is.read(buffer))) {
            os.write(buffer, 0, n);
        }
    }
}
