#include <kore/kore.h>
#include <kore/http.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdlib.h>
#include <inttypes.h>
#include <unistd.h>
#include <stdbool.h>

#include "systemd.h"
#include "sess.h"
#include "db.h"

int		serve_static(struct http_request *) __attribute__((visibility("default")));
int		serve_index(struct http_request *) __attribute__((visibility("default")));
int		total_energy(struct http_request *) __attribute__((visibility("default")));
int		device_energy(struct http_request *) __attribute__((visibility("default")));
int		get_data(struct http_request *req)__attribute__((visibility("default")));
int		register_user(struct http_request *req) __attribute__((visibility("default")));

#ifdef DEBUG_MODE
#define RET_ERROR(req, msg, ...) do { http_response(req, 500, NULL, 0); fprintf(stderr, msg "\n", ## __VA_ARGS__); return KORE_RESULT_OK; } while(0)
#else
#define RET_ERROR(req, ...) do { http_response(req, 500, NULL, 0); return KORE_RESULT_OK; } while(0)
#endif

int
serve_index(struct http_request *req)
{
    http_response_header(req, "Location", "/static?file=index.html");
	http_response(req, 302, NULL, 0);
	return (KORE_RESULT_OK);
}

int serve_static(struct http_request *req)
{
    http_populate_get(req);
    char *filename;
    int res = http_argument_get_string(req, "file", &filename);
    if (!res)
        return res;

    char *ext = strrchr(filename, '.');
    if (ext == NULL)
        RET_ERROR(req, "file has no extension");

    char *type;
    if (strcmp(ext, ".css") == 0)
        type = "text/css";
    else if (strcmp(ext, ".js") == 0)
        type = "text/javascript";
    else if (strcmp(ext, ".gif") == 0)
        type = "image/gif";
    else if (strcmp(ext, ".jpg") == 0)
        type = "image/jpeg";
    else if (strcmp(ext, ".png") == 0)
        type = "image/png";
    else
        type = "text/html";

    char full_path[strlen(filename) + 8];
    strcpy(full_path, "static/");
    strncat(full_path, filename, sizeof(full_path));

    if (strstr("..", filename)) // TODO: this is a bug! (reversed parameters)
        RET_ERROR(req, "directory traversal");

    FILE *file = fopen(full_path, "r");
    if (file == NULL)
        RET_ERROR(req, "file not found?");

    struct stat stat;
    res = fstat(fileno(file), &stat);
    if (res != 0)
        goto err_file;

    {
        char *data = calloc(1, stat.st_size);
        if (fread(data, stat.st_size, 1, file) != 1) {
            free(data);
            goto err_file;
        }

        fclose(file);
        file = NULL;

        http_response_header(req, "content-type", type);
        http_response(req, 200, data, stat.st_size);
        free(data);
    }

    return KORE_RESULT_OK;
err_file:
    fclose(file);
    RET_ERROR(req, "stat failed");
}
static double runtime_seconds_to_kWh(double seconds) {
    long ticks_per_second = sysconf(_SC_CLK_TCK);
    double cpu_seconds = (seconds) / (double)ticks_per_second;
    double cpu_hours = cpu_seconds / 3600;
    double computer_kilowatt = 0.2;
    return computer_kilowatt * cpu_hours;
}

int total_energy(struct http_request *req) {
    http_response_header(req, "content-type", "application/x-power-usage");

    FILE *file = fopen("/proc/uptime", "r");
    if (!file)
        RET_ERROR(req, "no uptime");

    double total, idle;
    int res = fscanf(file, "%le %le", &total, &idle);
    fclose(file);
    if (res != 2)
        RET_ERROR(req, "uptime scanf failed");

    char outp[100];
    int len = snprintf(outp, sizeof(outp), "%le", runtime_seconds_to_kWh(total - idle));
    http_response(req, 200, outp, len);
    return KORE_RESULT_OK;
}
static bool get_svc_name(const char *svc_name, char **object_path) {
    bool ret = false;
    GError *error = NULL;

    Systemd1Manager *manager = systemd1_manager_proxy_new_for_bus_sync(G_BUS_TYPE_SYSTEM,
            G_DBUS_OBJECT_MANAGER_CLIENT_FLAGS_NONE, "org.freedesktop.systemd1",
            "/org/freedesktop/systemd1", NULL, &error);
    if (manager == NULL) {
        fprintf(stderr, "manager == NULL\n");
        goto out;
    }

    gboolean ok = systemd1_manager_call_get_unit_sync(manager, svc_name, object_path, NULL, &error);
    if (!ok) {
        fprintf(stderr, "!ok: %s\n", error->message);
        goto out;
    }

    ret = true;

out:
    if (manager != NULL)
        g_object_unref(manager);
    return ret;
}

static bool get_svc_pid(const char *object_path, pid_t *pid) {
    bool ret = false;
    GError *error = NULL;

    Systemd1Service *service = systemd1_service_proxy_new_for_bus_sync(G_BUS_TYPE_SYSTEM,
            G_DBUS_OBJECT_MANAGER_CLIENT_FLAGS_NONE, "org.freedesktop.systemd1", object_path, NULL, &error);
    if (service == NULL) {
        goto out;
    }

    guint value = systemd1_service_get_main_pid(service);
    *pid = value;
    ret = true;

out:
    if (service != NULL)
        g_object_unref(service);
    return ret;
}

int device_energy(struct http_request *req) {
    http_populate_post(req);

    char *device;
    int res = http_argument_get_string(req, "device", &device);
    if (!res) {
        RET_ERROR(req, "queried device is missing");
    }

    pid_t pid = 0;
    char svc_name[29];
    const char *query_svc = device;
    if (!strcmp(device, "alexa"))
        query_svc = "uwsgi";
    else if (!strcmp(device, "smartscale"))
        query_svc = "dbus";
    else if (!strcmp(device, "toilet"))
        query_svc = "nginx";
    svc_name[0] = '\0';
    strcat(svc_name, query_svc);
    if (strlen(svc_name) > sizeof(svc_name)) {
        RET_ERROR(req, "device name too long");
    }
    strncat(svc_name, ".service", sizeof(svc_name));

    char *email = NULL;
    char *password = NULL;
    char *obj_path = NULL;
    res = http_argument_get_string(req, "email", &email);
    res = res == KORE_RESULT_OK ? http_argument_get_string(req, "password", &password) : res;
    if (res != KORE_RESULT_OK)
        return res;

    char *device_names[20];
    char *reasons[20];
    uint32_t uids[20];
    res = get_devices(email, password, device_names, reasons, uids);
    bool found = false;
    for (size_t i = 0; i < 20 && device_names[i]; i++) {
        if (strcmp(device, device_names[i]) == 0) {
            found = true;
        }
    }
    if (!found) {
        RET_ERROR(req, "no permission for this device");
    }

    char name[4096] = "-offline-";
    int utime = 0, stime = 0;
    bool ok = get_svc_name(svc_name, &obj_path);
    if (ok) {
        ok = get_svc_pid(obj_path, &pid);
        g_free(obj_path);
    }

    obj_path = NULL;
    if (ok && pid != 0) {
        http_response_header(req, "content-type", "application/x-power-usage");
        char fname[100];
        snprintf(fname, sizeof(fname), "/proc/%d/stat", pid);
        FILE *file = fopen(fname, "r");
        if (!file) {
            RET_ERROR(req, "could not open /proc/%d/stat", pid);
        }

        res = fscanf(file, "%*d (%4095[^)]) %*c %*d %*d %*d %*d %*d %*d %*d "
                   "%*d %*d %*d %d %d %*d %*d %*d %*d %*d %*d %*d %*d %*d "
                   "%*d %*d %*d %*d %*d %*u", name, &utime, &stime);
        fclose(file);
        if (res != 3)
            RET_ERROR(req, "scanf /proc/<x>/stat failed?");
    }

    char outp[100];
    int len = snprintf(outp, sizeof(outp), "%s\n%le", name,
            runtime_seconds_to_kWh(utime + stime));
    http_response(req, 200, outp, len);
    return KORE_RESULT_OK;
}


static int show_challenge(struct http_request *req) {
    http_response_header(req, "content-type", "text/plain");
    char chall[33];
    if (!new_chall(chall)) {
        RET_ERROR(req, "challenge creation failed");
    }

    http_response(req, 200, chall, 32);
    return KORE_RESULT_OK;
}

int get_data(struct http_request *req) {
    http_populate_post(req);
    char *sig_hex = NULL;
    char *chall_hex = NULL;
    int res = http_argument_get_string(req, "chall", &chall_hex);
    res = res == KORE_RESULT_OK ? http_argument_get_string(req, "sig", &sig_hex) : res;
    if (res == KORE_RESULT_ERROR) {
        return show_challenge(req);
    } else {
        size_t len = strlen(sig_hex);
        if (len % 2) {
            RET_ERROR(req, "invalid signature length");
        }
        uint8_t sig[len/2];
        if (!unhexlify(sig_hex, sig)) {
            RET_ERROR(req, "invalid signature format");
        }

        len = strlen(chall_hex);
        if (len % 2) {
            RET_ERROR(req, "invalid challenge length");
        }

        bool ok = validate_chall(chall_hex, sig, sizeof(sig));
        if (!ok) {
            return show_challenge(req);
        }

        // provider can also assign devices
        char *email = NULL, *device = NULL, *reason = NULL;
        res = http_argument_get_string(req, "email", &email);
        res = res == KORE_RESULT_OK ? http_argument_get_string(req, "device", &device) : res;
        res = res == KORE_RESULT_OK ? http_argument_get_string(req, "reason", &reason) : res;
        if (res == KORE_RESULT_OK) {
            res = assign_device(email, device, reason);
            if (res != KORE_RESULT_OK) {
                RET_ERROR(req, "assigning new device owner failed");
            }
        }

        http_response_header(req, "content-type", "text/plain");

        char *device_names[20];
        char *reasons[20];
        uint32_t uids[20];
        res = get_devices(NULL, NULL, device_names, reasons, uids);
        if (res == KORE_RESULT_ERROR) {
            RET_ERROR(req, "failure to query devices");
        }
        struct kore_buf *outp = kore_buf_alloc(0);
        for (size_t i = 0; i < 20 && device_names[i] && reasons[i]; i++) {
            kore_buf_appendf(outp, "%d,%s,%s\n", uids[i], device_names[i], reasons[i]);
            free(device_names[i]);
            free(reasons[i]);
        }
        char *buf = kore_buf_stringify(outp, &len);
        http_response(req, 200, buf, len);
        kore_buf_free(outp);
    }
    return KORE_RESULT_OK;
}

int register_user(struct http_request *req) {
    http_populate_post(req);
    char *email = NULL;
    char *password = NULL;
    char *password_confirm = NULL;
    int res = http_argument_get_string(req, "email", &email);
    res = res == KORE_RESULT_OK ? http_argument_get_string(req, "password", &password) : res;
    res = res == KORE_RESULT_OK ? http_argument_get_string(req, "password_confirm", &password_confirm) : res;
    if (res != KORE_RESULT_OK)
        return res;
    if (strcoll(password_confirm, password) != 0) {
        http_response(req, 409, "The passwords do not match.", 0);
        return KORE_RESULT_OK;
    }

    res = insert_user(email, password);
    if (res == KORE_RESULT_OK)
        http_response(req, 200, "OK", 0);
    else
        RET_ERROR(req, "user not inserted");

    return KORE_RESULT_OK;
}
