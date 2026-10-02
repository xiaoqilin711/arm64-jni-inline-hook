/*
 * resource_api_dump.c — end-to-end example: hook a JNI method and dump its
 * string arguments plus the return object's fields to logcat + a file.
 *
 * This mirrors the shape of the original engagement (a ServiceWorker-style
 * "resourceApi(String url, String method, String body, String header, boolean)"
 * method that is the single choke point for all network requests). Adapt the
 * three knobs below to your target; everything else is generic.
 *
 * Build:   ndk-build or clang (see ../build.sh)
 * Deploy:  load the .so via your firmware's arbitrary-.so-injection path
 *          (NOT Frida — the whole point is to leave no /memfd:frida-agent map).
 */

#include <jni.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <android/log.h>
#include <link.h>

#include "jnihook.h"

/* ---- target knobs (site/target specific — parameterize these) ---- */
#define TARGET_SO   "libtarget.so"          /* library holding the method   */
#define TARGET_OFF  0x637b1cUL              /* offset of the JNI method      */
#define OUT_FILE    "/data/local/tmp/capture.txt"
#define LOG_TAG     "jnihook-demo"

/* ---- dump one k/v pair to logcat and (optionally) a file ---- */
static void dump_kv(FILE* f, const char* k, const char* v) {
    if (!v) v = "(null)";
    __android_log_print(ANDROID_LOG_INFO, LOG_TAG, "%s=%s", k, v);
    if (f) fprintf(f, "%s=%s\n", k, v);
}

/* ---- read a String field from the return object via reflection ---- */
static void dump_string_field(JNIEnv* env, jobject obj, FILE* f,
                              const char* name, const char* sig) {
    jclass cls = (*env)->GetObjectClass(env, obj);
    if (!cls) return;
    jmethodID m = (*env)->GetMethodID(env, cls, name, sig);
    if (m) {
        jstring s = (jstring)(*env)->CallObjectMethod(env, obj, m);
        if (s) {
            const char* c = (*env)->GetStringUTFChars(env, s, NULL);
            dump_kv(f, name, c);
            if (c) (*env)->ReleaseStringUTFChars(env, s, c);
            (*env)->DeleteLocalRef(env, s);
        }
    }
    if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
    (*env)->DeleteLocalRef(env, cls);
}

/*
 * The handler. Signature is the generic jni_hook_handler_t; cast the raw
 * argument words back to their real JNI types.
 *
 *   env        = JNIEnv*
 *   thiz       = this (x1)
 *   url/method/body/header/flag = the method's own args (x2..x6)
 */
static void* on_resource_api(void* env, void* thiz, void* a1, void* a2,
                             void* a3, void* a4, void* a5, void** orig) {
    JNIEnv* e = (JNIEnv*)env;
    jstring url    = (jstring)a1;
    jstring method = (jstring)a2;
    jstring body   = (jstring)a3;
    jstring header = (jstring)a4;
    jboolean flag  = (jboolean)(intptr_t)a5;

    /* orig is typed as jni_hook_handler_t; cast to the real JNI signature. */
    typedef jobject (*resource_api_t)(JNIEnv*, jobject, jstring, jstring,
                                      jstring, jstring, jboolean);
    resource_api_t real = (resource_api_t)*orig;

    FILE* f = fopen(OUT_FILE, "a");
    if (f) fprintf(f, "\n===== resourceApi @%ld =====\n", (long)time(NULL));

#define DUMP_JSTR(name, js) \
    do { if (js) { const char* c = (*e)->GetStringUTFChars(e, js, NULL); \
         dump_kv(f, name, c); if (c) (*e)->ReleaseStringUTFChars(e, js, c); } \
         else dump_kv(f, name, "(null)"); } while (0)
    DUMP_JSTR("URL", url);
    DUMP_JSTR("METHOD", method);
    DUMP_JSTR("BODY", body);
    DUMP_JSTR("HEADER", header);
#undef DUMP_JSTR
    { char b[16]; snprintf(b, sizeof(b), "%d", (int)flag); dump_kv(f, "FLAG", b); }

    /* call the original */
    jobject resp = real(e, (jobject)thiz, url, method, body, header, flag);

    /* dump response fields (adapt names/signatures to your ApiResponse) */
    if (resp) {
        dump_string_field(e, resp, f, "getCode", "()Ljava/lang/String;");
        dump_string_field(e, resp, f, "getHeader", "()Ljava/lang/String;");
        __android_log_print(ANDROID_LOG_INFO, LOG_TAG, "got response object");
    }

    if (f) { fflush(f); fclose(f); }
    return (void*)resp;
}

/* ---- constructor: spawn a worker that waits for the target lib, then hooks */
#include <pthread.h>
#include <unistd.h>

static int phdr_cb(struct dl_phdr_info* info, size_t size, void* data) {
    (void)size;
    uintptr_t* base = (uintptr_t*)data;
    if (info->dlpi_name && strstr(info->dlpi_name, TARGET_SO)) {
        *base = (uintptr_t)info->dlpi_addr;
        return 1; /* stop iteration */
    }
    return 0;
}
static uintptr_t resolve_base(void) {
    uintptr_t base = 0;
    dl_iterate_phdr(phdr_cb, &base);
    return base;
}

static void* worker(void* arg) {
    (void)arg;
    uintptr_t base = 0;
    for (int i = 0; i < 600; i++) {          /* wait up to ~60s for the lib */
        base = resolve_base();
        if (base) break;
        usleep(100 * 1000);
    }
    if (!base) {
        __android_log_print(ANDROID_LOG_WARN, LOG_TAG, "%s not found", TARGET_SO);
        return NULL;
    }
    uintptr_t target = base + TARGET_OFF;
    __android_log_print(ANDROID_LOG_INFO, LOG_TAG,
                        "%s base=%p target=%p", TARGET_SO, (void*)base, (void*)target);

    void* orig = NULL;
    int r = jnihook_install((void*)target, on_resource_api, &orig);
    __android_log_print(ANDROID_LOG_INFO, LOG_TAG,
                        "jnihook_install ret=%d orig=%p", r, orig);
    return NULL;
}

__attribute__((constructor))
static void on_load(void) {
    __android_log_print(ANDROID_LOG_INFO, LOG_TAG, "loaded pid=%d", getpid());
    pthread_t t;
    pthread_create(&t, NULL, worker, NULL);
    pthread_detach(t);
}
