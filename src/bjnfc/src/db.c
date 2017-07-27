#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>

#include <kore/kore.h>
#include <kore/http.h>
#include <kore/pgsql.h>

#include "db.h"

static void init_db_callback(void) {
    int res = kore_pgsql_register("db", "postgresql://");
    if (res != KORE_RESULT_OK) {
        fprintf(stderr, "No DB connection.\n");
        exit(1);
    }
}
void init_db(void) {
    static pthread_once_t once_control = PTHREAD_ONCE_INIT;
    int res = pthread_once(&once_control, init_db_callback);
    if (res != 0) {
        exit(1);
    }
}
static int pgsql_query_init(struct kore_pgsql *pgsql, struct http_request *req, const char *dbname, int flags) {
    init_db();
    int res;
    do {
        res = kore_pgsql_query_init(pgsql, req, dbname, flags);
    } while (res == KORE_RESULT_ERROR && pgsql->state == KORE_PGSQL_STATE_INIT);
    return res;
}

static int expire_challs(void) {
    struct kore_pgsql sql;
    if (pgsql_query_init(&sql, NULL, "db", KORE_PGSQL_SYNC) != KORE_RESULT_OK) {
        return KORE_RESULT_ERROR;
    }

    const char *query = "delete from challenges where expiry < current_timestamp;";

    int ret = kore_pgsql_query(&sql, query);
    kore_pgsql_cleanup(&sql);
    return ret;
}

bool chall_exists(const char chall[33]) {
    expire_challs();

    struct kore_pgsql sql;
    if (pgsql_query_init(&sql, NULL, "db", KORE_PGSQL_SYNC) != KORE_RESULT_OK) {
        return false;
    }

    const char *query = "select count(*) from challenges where value = '%s';";
    char q[strlen(query) + 32 + 1];
    snprintf(q, sizeof(q), query, chall);

    bool ok = false;
    if (kore_pgsql_query(&sql, q) != KORE_RESULT_OK) {
        goto clean;
    }
    long cnt = strtol(kore_pgsql_getvalue(&sql, 0, 0), NULL, 10);
    ok = cnt >= 1 && cnt != LONG_MAX;

clean:
    kore_pgsql_cleanup(&sql);
    return ok;
}

int insert_chall(const char chall[33]) {
    expire_challs();

    struct kore_pgsql sql;
    if (pgsql_query_init(&sql, NULL, "db", KORE_PGSQL_SYNC) != KORE_RESULT_OK) {
        return KORE_RESULT_ERROR;
    }

    int ret = KORE_RESULT_ERROR;

    const char *query = "insert into challenges (value, expiry) values('%s', current_timestamp + (interval '15 minutes'));";
    char q[strlen(query) + 33];
    snprintf(q, sizeof(q), query, chall);

    if (kore_pgsql_query(&sql, q) != KORE_RESULT_OK) {
        goto clean;
    }

    ret = KORE_RESULT_OK;

clean:
    kore_pgsql_cleanup(&sql);
    return ret;
}

int insert_user(const char *email, const char *pass) {
    if (strpbrk(email, "\"\0\0\0\0\0\0") || strpbrk(pass, "'\0\0\0\0\0\0")) {
        return KORE_RESULT_ERROR;
    }
    struct kore_pgsql sql;
    if (pgsql_query_init(&sql, NULL, "db", KORE_PGSQL_SYNC) != KORE_RESULT_OK) {
        return KORE_RESULT_ERROR;
    }

    int ret = KORE_RESULT_ERROR;

    const char *query = "insert into users (email, password) values('%s', crypt('%s', gen_salt('bf')));";
    char q[strlen(query) + strlen(email) + strlen(pass) + 1];
    snprintf(q, sizeof(q), query, email, pass);

    ret = kore_pgsql_query(&sql, q);
    if (ret != KORE_RESULT_OK) {
        goto clean;
    }

clean:
    kore_pgsql_cleanup(&sql);
    return ret;
}

int get_devices(const char *email, const char *pass, char *device_names[20], char *reasons[20], uint32_t uids[20]) {
//int login(const char *email, const char *pass, uint32_t *id) {
    struct kore_pgsql sql;
    if (pgsql_query_init(&sql, NULL, "db", KORE_PGSQL_SYNC) != KORE_RESULT_OK) {
        return KORE_RESULT_ERROR;
    }

    const char *query;
    size_t query_len = 0;
    if (email && pass) {
        if (strpbrk(email, "'\0\0\0\0\0\0") || strpbrk(pass, "'\0\0\0\0\0\0")) {
            return KORE_RESULT_ERROR;
        }

        query = "select owners.user_id, devices.name, owners.reason from devices left join owners on devices.id = owners.device_id left join users on owners.user_id = users.id WHERE users.email = '%s' and password like crypt('%s', password);";
        query_len = strlen(query) + strlen(email) + strlen(pass) + 1;
    } else {
        query = "select owners.user_id, devices.name, owners.reason from devices left join owners on devices.id = owners.device_id;";
        query_len = strlen(query);
    }
    char q[query_len];
    snprintf(q, sizeof(q), query, email, pass);

    int ret = KORE_RESULT_ERROR;
    if (kore_pgsql_query(&sql, q) != KORE_RESULT_OK) {
        goto clean;
    }

    int affected = kore_pgsql_ntuples(&sql);
    if (affected == 0 || affected >= 19) {
        goto clean;
    }
    for (int i = 0; i < affected; i++) {
        long v = strtol(kore_pgsql_getvalue(&sql, i, 0), NULL, 0);
        if (v < 0 || v == LONG_MAX || v >= INT_MAX)
            goto clean;
        uids[i] = v;
        device_names[i] = strdup(kore_pgsql_getvalue(&sql, i, 1));
        reasons[i] = strdup(kore_pgsql_getvalue(&sql, i, 2));
    }
    device_names[affected] = NULL;
    reasons[affected] = NULL;
    ret = KORE_RESULT_OK;

clean:
    kore_pgsql_cleanup(&sql);
    return ret;
}

int assign_device(const char *email, const char *device_name, const char *reason) {
    int ret = KORE_RESULT_ERROR;
    if (strpbrk(email, "'\0\0\0\0\0\0") || strpbrk(reason, "\n,'\0\0\0\0\0\0") ||
            strpbrk(device_name, "'\0\0\0\0\0\0")) {
        goto clean;
    }
    struct kore_pgsql sql;
    if (pgsql_query_init(&sql, NULL, "db", KORE_PGSQL_SYNC) != KORE_RESULT_OK) {
        goto clean;
    }
    uint32_t uid;
    {
        const char *query = "select max(id) from users where email = '%s';";
        char q1[strlen(query) + strlen(email) + 1];
        snprintf(q1, sizeof(q1), query, email);
        if (kore_pgsql_query(&sql, q1) != KORE_RESULT_OK ) {
            goto clean;
        }
        int affected = kore_pgsql_ntuples(&sql);
        if (affected != 1) {
            goto clean;
        }

        uid = strtol(kore_pgsql_getvalue(&sql, 0, 0), NULL, 0);
    }

    {
        const char *query = "insert into owners (user_id, reason, device_id) values(%u, '%s', (select id from devices where name = '%s')) on conflict (device_id) do update set user_id = excluded.user_id, reason = excluded.reason;";
        char q2[strlen(query) + 3*sizeof(uint32_t) + strlen(reason) + 3 * sizeof(uint32_t) + 1];
        snprintf(q2, sizeof(q2), query, uid, reason, device_name, uid, reason);

        if (kore_pgsql_query(&sql, q2) != KORE_RESULT_OK) {
            goto clean;
        }
    }

    ret = KORE_RESULT_OK;

clean:
    kore_pgsql_cleanup(&sql);
    return ret;
}
