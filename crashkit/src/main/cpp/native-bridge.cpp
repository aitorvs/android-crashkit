#include <jni.h>
#include <string>
#include <unistd.h>
#include "client/crashpad_client.h"
#include "client/crash_report_database.h"
#include "client/settings.h"
#include "client/annotation.h"
#include "client/crashpad_info.h"
#include "util/misc/capture_context.h"   // CaptureContext
#include "util/misc/uuid.h"
#include <dlfcn.h>
#include <fcntl.h>      // open, O_WRONLY, O_CREAT, O_TRUNC
#include <csignal>
#if defined(__ANDROID__)
#include <ucontext.h>   // defines ucontext_t on bionic/NDK
#else
#include <sys/ucontext.h>
#endif

#include "base/files/file_path.h"
#include "process.h"

#include <memory>
static std::unique_ptr<crashpad::CrashpadClient> g_client;
static std::unique_ptr<std::vector<std::string>> g_env;
void stackFrame1();
void stackFrame2();
void stackFrame3();
void crash();

using namespace base;
using namespace crashpad;
using namespace std;

// ---- Crash marker ----
// Fixed-size C array: safe to read from a signal handler (no heap, no locks).
// Written once at init time, read-only thereafter.
static char g_crash_marker_path[512] = {};

// Crashpad's FirstChanceHandler signature: bool (*)(int, siginfo_t*, ucontext_t*)
static bool FirstChanceHandler(int /*signo*/, siginfo_t* /*info*/, ucontext_t* /*uctx*/) {
    // Only async-signal-safe operations here!
    // Create the marker file so the next launch knows a crash occurred.
    if (g_crash_marker_path[0] != '\0') {
        int fd = open(g_crash_marker_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
        if (fd >= 0) close(fd);
    }
    // Return false so Crashpad continues to handle the crash.
    return false;
}

extern "C" JNIEXPORT jboolean JNICALL
Java_com_duckduckgo_android_1crashkit_Crashpad_initializeCrashpad(
        JNIEnv* env,
        jobject /* this */,
        jstring appDataDir,
        jstring libDir,
        jstring jPlatform,
        jstring jVersion,
        jstring jOsVersion,
        jstring jUploadUrl,
        jboolean jUploadsEnabled,
        jboolean jNoRateLimit,
        jobjectArray jAnnotationKeys,
        jobjectArray jAnnotationValues,
        jstring jMarkerPath
) {
    // Convert Java strings to C++ with fallback "unknown"
    auto getOrUnknown = [&](jstring jstr) -> string {
        if (jstr == nullptr) return "unknown";
        const char* chars = env->GetStringUTFChars(jstr, nullptr);
        string result = (chars != nullptr) ? chars : "unknown";
        env->ReleaseStringUTFChars(jstr, chars);
        if (result.empty()) result = "unknown";
        return result;
    };

    // Device file paths
    string nativeLibraryDir = getOrUnknown(libDir);
    string dataDir = getOrUnknown(appDataDir);
    string platform = getOrUnknown(jPlatform);
    string version = getOrUnknown(jVersion);
    string osVersion = getOrUnknown(jOsVersion);
    string process = get_process_name();

    // Crashpad file paths
    FilePath handler(nativeLibraryDir);
    FilePath reportsDir(dataDir + "/crashpad");
    FilePath metricsDir(dataDir + "/crashpad/metrics");

    // Upload URL — empty string means local-only (no upload)
    const char* urlChars = (jUploadUrl != nullptr) ? env->GetStringUTFChars(jUploadUrl, nullptr) : nullptr;
    string url = (urlChars != nullptr) ? urlChars : "";
    if (urlChars != nullptr) env->ReleaseStringUTFChars(jUploadUrl, urlChars);

    // Crashpad annotations
    map<string, string> annotations;
    annotations["format"] = "minidump";     // Required: Crashpad setting to save crash as a minidump
    annotations["process"] = process;       // Required: process
    annotations["platform"] = platform;     // Required: platform
    annotations["version"] = version;       // Required: app version
    annotations["osVersion"] = osVersion;   // Required: OS version

    // Merge extra annotations passed from the caller
    jsize annotationCount = env->GetArrayLength(jAnnotationKeys);
    for (jsize i = 0; i < annotationCount; i++) {
        auto jKey = (jstring) env->GetObjectArrayElement(jAnnotationKeys, i);
        auto jVal = (jstring) env->GetObjectArrayElement(jAnnotationValues, i);
        const char* key = env->GetStringUTFChars(jKey, nullptr);
        const char* val = env->GetStringUTFChars(jVal, nullptr);
        annotations[key] = val;
        env->ReleaseStringUTFChars(jKey, key);
        env->ReleaseStringUTFChars(jVal, val);
        env->DeleteLocalRef(jKey);
        env->DeleteLocalRef(jVal);
    }

    // Crashpad arguments
    vector<string> arguments;
    if (jNoRateLimit == JNI_TRUE) {
        arguments.emplace_back("--no-rate-limit");
    }
    // Allow exactly the annotation keys we set ourselves — the hardcoded ones above plus
    // whatever the caller passed in extraAnnotations. Any annotation injected by WebView
    // or other third-party code (guid, variations, gpu-*, vulkan-*, …) is excluded.
    for (const auto& kv : annotations) {
        arguments.push_back("--allow-annotation=" + kv.first);
    }
    // Passthrough keys set by the system/WebView that are useful for debugging but not PII.
    // We don't set these ourselves so they can't go through the annotations map above.
    for (const auto& key : {"ptype", "osarch"}) {
        arguments.push_back("--allow-annotation=" + string(key));
    }

    // Crashpad local database
    unique_ptr<CrashReportDatabase> crashReportDatabase = CrashReportDatabase::Initialize(reportsDir);
    if (crashReportDatabase == nullptr) return false;

    // Enable automated crash uploads
    Settings *settings = crashReportDatabase->GetSettings();
    if (settings == nullptr) return false;
    settings->SetUploadsEnabled(jUploadsEnabled == JNI_TRUE);

    // File paths of attachments to be uploaded with the minidump file at crash time - default bundle limit is 20MB
    vector<FilePath> attachments;
    // commented out to reduce the PII surface
//    FilePath attachment(dataDir + "/attachment.txt");
//    attachments.push_back(attachment);

    // Start Crashpad crash handler
    auto *client = new CrashpadClient();
    bool status = client->StartHandler(
            handler,
            reportsDir,
            metricsDir,
            url,
            annotations,
            arguments,
            false, false,
            attachments
    );

    if (!status) {
        delete client;
        return false;
    }
    g_client.reset(client);

    // Minimize captured memory to reduce risk of PII: disable indirectly referenced memory
    if (auto* info = crashpad::CrashpadInfo::GetCrashpadInfo()) {
        info->set_gather_indirectly_referenced_memory(
                crashpad::TriState::kDisabled,
                /*limit=*/0
        );
    }

    // Register crash marker — written by FirstChanceHandler on crash,
    // consumed by Crashpad.init() on the next launch.
    if (jMarkerPath != nullptr) {
        const char* chars = env->GetStringUTFChars(jMarkerPath, nullptr);
        if (chars != nullptr && strlen(chars) < sizeof(g_crash_marker_path)) {
            memcpy(g_crash_marker_path, chars, strlen(chars) + 1);
            crashpad::CrashpadClient::SetFirstChanceExceptionHandler(&FirstChanceHandler);
        }
        env->ReleaseStringUTFChars(jMarkerPath, chars);
    }

    return status;
}

extern "C" JNIEXPORT jboolean JNICALL
Java_com_duckduckgo_android_1crashkit_Crashpad_nativeCrash(
        JNIEnv* env,
        jobject /* this */) {

    stackFrame1();

    return true;
}

extern "C" JNIEXPORT jboolean JNICALL
Java_com_duckduckgo_android_1crashkit_Crashpad_nativeDumpWithoutCrash(
        JNIEnv*, jobject /* this */) {

    crashpad::NativeCPUContext ctx{};
    crashpad::CaptureContext(&ctx);

    // Force a dump without crashing
    crashpad::CrashpadClient::DumpWithoutCrash(&ctx);
    return JNI_TRUE;
}

void stackFrame1() {
    stackFrame2();
}

void stackFrame2() {
    stackFrame3();
}

void stackFrame3() {
    crash();
}

void crash() {
    *(volatile int *)nullptr = 0;
}
