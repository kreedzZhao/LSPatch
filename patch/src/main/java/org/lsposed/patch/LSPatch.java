package org.lsposed.patch;

import static org.lsposed.lspatch.share.Constants.CONFIG_ASSET_PATH;
import static org.lsposed.lspatch.share.Constants.EMBEDDED_MODULES_ASSET_PATH;
import static org.lsposed.lspatch.share.Constants.LOADER_DEX_ASSET_PATH;
import static org.lsposed.lspatch.share.Constants.ORIGINAL_APK_ASSET_PATH;
import static org.lsposed.lspatch.share.Constants.PROXY_APP_COMPONENT_FACTORY;

import com.android.tools.build.apkzlib.sign.SigningExtension;
import com.android.tools.build.apkzlib.sign.SigningOptions;
import com.android.tools.build.apkzlib.zip.AlignmentRules;
import com.android.tools.build.apkzlib.zip.StoredEntry;
import com.android.tools.build.apkzlib.zip.ZFile;
import com.android.tools.build.apkzlib.zip.ZFileOptions;
import com.beust.ah.A;
import com.beust.jcommander.JCommander;
import com.beust.jcommander.Parameter;
import com.beust.jcommander.ParameterException;
import com.google.gson.Gson;
import com.wind.meditor.core.ManifestEditor;
import com.wind.meditor.property.AttributeItem;
import com.wind.meditor.property.ModificationProperty;
import com.wind.meditor.utils.NodeValue;

import org.apache.commons.io.FilenameUtils;
import org.lsposed.lspatch.share.Constants;
import org.lsposed.lspatch.share.LSPConfig;
import org.lsposed.lspatch.share.PatchConfig;
import org.lsposed.patch.util.ApkSignatureHelper;
import org.lsposed.patch.util.JavaLogger;
import org.lsposed.patch.util.Logger;
import org.lsposed.patch.util.ManifestParser;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Set;

public class LSPatch {

    static class PatchError extends Error {
        public PatchError(String message, Throwable cause) {
            super(message, cause);
        }

        PatchError(String message) {
            super(message);
        }
    }

    @Parameter(description = "apks")
    private List<String> apkPaths = new ArrayList<>();

    @Parameter(names = {"-h", "--help"}, help = true, order = 0, description = "Print this message")
    private boolean help = false;

    @Parameter(names = {"-o", "--output"}, description = "Output directory")
    private String outputPath = ".";

    @Parameter(names = {"-f", "--force"}, description = "Force overwrite exists output file")
    private boolean forceOverwrite = false;

    @Parameter(names = {"-d", "--debuggable"}, description = "Set app to be debuggable")
    private boolean debuggableFlag = false;

    @Parameter(names = {"-l", "--sigbypasslv"}, description = "Signature bypass level. 0 (disable), 1 (pm), 2 (pm+openat). default 0")
    private int sigbypassLevel = 0;

    @Parameter(names = {"-k", "--keystore"}, arity = 4, description = "Set custom signature keystore. Followed by 4 arguments: keystore path, keystore password, keystore alias, keystore alias password")
    private List<String> keystoreArgs = Arrays.asList(null, "123456", "key0", "123456");

    @Parameter(names = {"--manager"}, description = "Use manager (Cannot work with embedding modules)")
    private boolean useManager = false;

    @Parameter(names = {"-r", "--allowdown"}, description = "Allow downgrade installation by overriding versionCode to 1 (In most cases, the app can still get the correct versionCode)")
    private boolean overrideVersionCode = false;

    @Parameter(names = {"-v", "--verbose"}, description = "Verbose output")
    private boolean verbose = false;

    @Parameter(names = {"-m", "--embed"}, description = "Embed provided modules to apk")
    private List<String> modules = new ArrayList<>();

    private static final String ANDROID_MANIFEST_XML = "AndroidManifest.xml";
    private static final HashSet<String> ARCHES = new HashSet<>(Arrays.asList(
            "armeabi-v7a",
            "arm64-v8a",
            "x86",
            "x86_64"
    ));

    private static final ZFileOptions Z_FILE_OPTIONS = new ZFileOptions().setAlignmentRule(AlignmentRules.compose(
            AlignmentRules.constantForSuffix(".so", 4096),
            AlignmentRules.constantForSuffix(ORIGINAL_APK_ASSET_PATH, 4096)
    ));

    private final JCommander jCommander;

    private final Logger logger;

    public LSPatch(Logger logger, String... args) {
        jCommander = JCommander.newBuilder().addObject(this).build();
        try {
            jCommander.parse(args);
        } catch (ParameterException e) {
            logger.e(e.getMessage() + "\n");
            help = true;
        }
        if (apkPaths == null || apkPaths.isEmpty()) {
            logger.e("No apk specified\n");
            help = true;
        }
        if (!modules.isEmpty() && useManager) {
            logger.e("Should not use --embed and --manager at the same time\n");
            help = true;
        }

        this.logger = logger;
        logger.verbose = verbose;
    }

    public static void main(String... args) throws IOException {
        LSPatch lspatch = new LSPatch(new JavaLogger(), args);
        if (lspatch.help) {
            lspatch.jCommander.usage();
            return;
        }
        try {
            lspatch.doCommandLine();
        } catch (PatchError e) {
            e.printStackTrace(System.err);
        }
    }

    public void doCommandLine() throws PatchError, IOException {
        for (var apk : apkPaths) {
            File srcApkFile = new File(apk).getAbsoluteFile();

            String apkFileName = srcApkFile.getName();

            var outputDir = new File(outputPath);
            outputDir.mkdirs();

            File outputFile = new File(outputDir, String.format(
                    Locale.getDefault(), "%s-%d-lspatched.apk",
                    FilenameUtils.getBaseName(apkFileName),
                    LSPConfig.instance.VERSION_CODE)
            ).getAbsoluteFile();

            if (outputFile.exists() && !forceOverwrite)
                throw new PatchError(outputPath + " exists. Use --force to overwrite");
            logger.i("Processing " + srcApkFile + " -> " + outputFile);

            patch(srcApkFile, outputFile);
        }
    }

    public void patch(File srcApkFile, File outputFile) throws PatchError, IOException {
        if (!srcApkFile.exists())
            throw new PatchError("The source apk file does not exit. Please provide a correct path.");

        outputFile.delete();

        logger.d("apk path: " + srcApkFile);

        logger.i("Parsing original apk...");

        try (var dstZFile = ZFile.openReadWrite(outputFile, Z_FILE_OPTIONS);
             // 原始 apk 存入生成 apk asseets 目录，并且更名为 origin.apk
             var srcZFile = dstZFile.addNestedZip((ignore) -> ORIGINAL_APK_ASSET_PATH, srcApkFile, false)) {

            // sign apk
            try {
                var keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
                // -k 参数动态指定
                // 使用方式 -k keystorePath keystorePassword keystoreAlias keystoreAliasPassword
                if (keystoreArgs.get(0) == null) {
                    logger.i("Register apk signer with default keystore...");
                    try (var is = getClass().getClassLoader().getResourceAsStream("assets/keystore")) {
                        keyStore.load(is, keystoreArgs.get(1).toCharArray());
                    }
                } else {
                    logger.i("Register apk signer with custom keystore...");
                    try (var is = new FileInputStream(keystoreArgs.get(0))) {
                        keyStore.load(is, keystoreArgs.get(1).toCharArray());
                    }
                }
                // 设置密码
                var entry = (KeyStore.PrivateKeyEntry) keyStore.getEntry(keystoreArgs.get(2), new KeyStore.PasswordProtection(keystoreArgs.get(3).toCharArray()));
                /*
                设置签名选项 apkzlib 标准用法
                minSdkVersion: 28 最小的 sdk 版本
                v2SigningEnabled: true 是否启用 v2 签名
                certificates: (X509Certificate[]) entry.getCertificateChain() 证书链
                key: entry.getPrivateKey() 私钥
                 */
                new SigningExtension(SigningOptions.builder()
                        .setMinSdkVersion(28)
                        .setV2SigningEnabled(true)
                        .setCertificates((X509Certificate[]) entry.getCertificateChain())
                        .setKey(entry.getPrivateKey())
                        .build()).register(dstZFile);
            } catch (Exception e) {
                throw new PatchError("Failed to register signer", e);
            }

            String originalSignature = null;
            // sigbypassLevel 为 0 时，不进行签名绕过，否则获取原始签名，用于绕过签名验证
            if (sigbypassLevel > 0) {
                originalSignature  = ApkSignatureHelper.getApkSignInfo(srcApkFile.getAbsolutePath());
                if (originalSignature == null || originalSignature.isEmpty()) {
                    throw new PatchError("get original signature failed");
                }
                logger.d("Original signature\n" + originalSignature);
            }

            // copy out manifest file from zlib
            var manifestEntry = srcZFile.get(ANDROID_MANIFEST_XML);
            if (manifestEntry == null)
                throw new PatchError("Provided file is not a valid apk");

            /*
            AppComponentFactory 的主要作用是根据配置文件（AndroidManifest.xml）中声明的组件信息，
            实例化对应的组件对象，并且为它们提供所需的上下文环境。
            这样，当应用程序启动时，它可以根据需要创建和初始化必要的组件
            往往在 AndroidManifest.xml 中还有配套的 activity、service、receiver、provider 等标签
            这里设置的 Factory 为 org.lsposed.lspatch.metaloader.LSPAppComponentFactoryStub
             */
            // parse the app appComponentFactory full name from the manifest file
            final String appComponentFactory;
            int minSdkVersion;
            try (var is = manifestEntry.open()) {
                var pair = ManifestParser.parseManifestFile(is);
                if (pair == null)
                    throw new PatchError("Failed to parse AndroidManifest.xml");
                appComponentFactory = pair.appComponentFactory;
                minSdkVersion = pair.minSdkVersion;
                logger.d("original appComponentFactory class: " + appComponentFactory);
                logger.d("original minSdkVersion: " + minSdkVersion);
            }

            logger.i("Patching apk...");
            // modify manifest
            final var config = new PatchConfig(useManager, debuggableFlag, overrideVersionCode, sigbypassLevel, originalSignature, appComponentFactory);
            final var configBytes = new Gson().toJson(config).getBytes(StandardCharsets.UTF_8);
            final var metadata = Base64.getEncoder().encodeToString(configBytes);
            // 主要修改 SDK 版本，debuggable 标志，appComponentFactory，metadata
            try (var is = new ByteArrayInputStream(modifyManifestFile(manifestEntry.open(), metadata, minSdkVersion))) {
                dstZFile.add(ANDROID_MANIFEST_XML, is);
            } catch (Throwable e) {
                throw new PatchError("Error when modifying manifest", e);
            }

            logger.i("Adding config...");
            // save lspatch config to asset..
            try (var is = new ByteArrayInputStream(configBytes)) {
                dstZFile.add(CONFIG_ASSET_PATH, is);
            } catch (Throwable e) {
                throw new PatchError("Error when saving config");
            }

            logger.i("Adding metaloader dex...");
            // metaloader.dex -> classes.dex
            try (var is = getClass().getClassLoader().getResourceAsStream(Constants.META_LOADER_DEX_ASSET_PATH)) {
                dstZFile.add("classes.dex", is);
            } catch (Throwable e) {
                throw new PatchError("Error when adding dex", e);
            }

            if (!useManager) {
                logger.i("Adding loader dex...");
                try (var is = getClass().getClassLoader().getResourceAsStream(LOADER_DEX_ASSET_PATH)) {
                    dstZFile.add(LOADER_DEX_ASSET_PATH, is);
                } catch (Throwable e) {
                    throw new PatchError("Error when adding assets", e);
                }

                logger.i("Adding native lib...");
                // copy so and dex files into the unzipped apk
                // do not put liblspatch.so into apk!lib because x86 native bridge causes crash
                for (String arch : ARCHES) {
                    // TODO 这里手动写死了
                    // 如果 manager 编译失败，只编译 patch-loader 就够了，并且只是编译
//                    ArrayList<String> arches = new ArrayList<>();
//                    arches.add("armeabi-v7a");
//                    arches.add("arm64-v8a");
//                    if (!arches.contains(arch)) continue;

                    String entryName = "assets/lspatch/so/" + arch + "/liblspatch.so";
                    try (var is = getClass().getClassLoader().getResourceAsStream(entryName)) {
                        dstZFile.add(entryName, is, false); // no compress for so
                    } catch (Throwable e) {
                        // More exception info
                        throw new PatchError("Error when adding native lib", e);
                    }
                    logger.d("added " + entryName);
                }

                logger.i("Embedding modules...");
                embedModules(dstZFile);
            }

            // create zip link
            logger.d("Creating nested apk link...");

            for (StoredEntry entry : srcZFile.entries()) {
                String name = entry.getCentralDirectoryHeader().getName();
                // 除了 dex AndroidManifest.xml 秘钥信息 其他的文件原样复制
                if (name.startsWith("classes") && name.endsWith(".dex")) continue;
                if (dstZFile.get(name) != null) continue;
                if (name.equals("AndroidManifest.xml")) continue;
                if (name.startsWith("META-INF") && (name.endsWith(".SF") || name.endsWith(".MF") || name.endsWith(".RSA"))) continue;
                srcZFile.addFileLink(name, name);
            }

            dstZFile.realign();

            logger.i("Writing apk...");
        }
        logger.i("Done. Output APK: " + outputFile.getAbsolutePath());
    }

    private void embedModules(ZFile zFile) {
        for (var module : modules) {
            File file = new File(module);
            try (var apk = ZFile.openReadOnly(new File(module));
                 var fileIs = new FileInputStream(file);
                 var xmlIs = Objects.requireNonNull(apk.get(ANDROID_MANIFEST_XML)).open()
            ) {
                var manifest = Objects.requireNonNull(ManifestParser.parseManifestFile(xmlIs));
                var packageName = manifest.packageName;
                logger.i("  - " + packageName);
                zFile.add(EMBEDDED_MODULES_ASSET_PATH + packageName + ".apk", fileIs);
            } catch (NullPointerException | IOException e) {
                logger.e(module + " does not exist or is not a valid apk file.");
            }
        }
    }

    private byte[] modifyManifestFile(InputStream is, String metadata, int minSdkVersion) throws IOException {
        ModificationProperty property = new ModificationProperty();

        if (overrideVersionCode)
            property.addManifestAttribute(new AttributeItem(NodeValue.Manifest.VERSION_CODE, 1));
        if (minSdkVersion < 28)
            property.addUsesSdkAttribute(new AttributeItem(NodeValue.UsesSDK.MIN_SDK_VERSION, "28"));
        property.addApplicationAttribute(new AttributeItem(NodeValue.Application.DEBUGGABLE, debuggableFlag));
        // 关键位置，入口类
        property.addApplicationAttribute(new AttributeItem("appComponentFactory", PROXY_APP_COMPONENT_FACTORY));
        property.addMetaData(new ModificationProperty.MetaData("lspatch", metadata));
        // TODO: replace query_all with queries -> manager
        if (useManager)
            property.addUsesPermission("android.permission.QUERY_ALL_PACKAGES");

        var os = new ByteArrayOutputStream();
        (new ManifestEditor(is, os, property)).processManifest();
        is.close();
        os.flush();
        os.close();
        return os.toByteArray();
    }
}
