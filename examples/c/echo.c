/*
 * examples/c/echo.c — minimal librustscale demo.
 *
 * Compile-only by default.  To run live:
 *   TS_E2E_AUTHKEY=tskey-... TS_E2E_TAILNET=... tools/ffi-smoke.sh --run
 *
 * Two nodes are created: one listens on port 4242, the other dials it and
 * sends "hello ffi".  The listener echoes it back.
 */
#include "../../include/rustscale.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#define SLEEP_MS(ms) Sleep(ms)
#else
#include <unistd.h>
#define SLEEP_MS(ms) usleep((ms) * 1000)
#endif

int main(void) {
    const char *authkey = getenv("TS_E2E_AUTHKEY");
    if (!authkey) {
        fprintf(stderr, "echo: TS_E2E_AUTHKEY not set; compile-only smoke test\n");
        return 0;
    }

    /* --- Server B (listener) --- */
    int b = ts_new();
    if (b < 0) { fprintf(stderr, "ts_new B: %d\n", b); return 1; }
    ts_set_hostname(b, "rustscale-ffi-echo-b");
    ts_set_authkey(b, authkey);
    ts_set_ephemeral(b, 1);

    int rc = ts_up(b);
    if (rc != 0) {
        char err[256];
        ts_errmsg(b, err, sizeof(err));
        fprintf(stderr, "ts_up B: %d: %s\n", rc, err);
        ts_close(b);
        return 1;
    }

    /* Read B's IP. */
    char status[4096];
    int sn = ts_status_json(b, status, sizeof(status));
    if (sn < 0) { fprintf(stderr, "status_json B: %d\n", sn); ts_close(b); return 1; }
    status[sn] = '\0';
    fprintf(stderr, "B status: %s\n", status);

    /* Extract first tailscale IP (naive JSON parse). */
    char ip_b[64] = {0};
    const char *key = "\"tailscale_ips\":[\"";
    char *p = strstr(status, key);
    if (p) {
        p += strlen(key);
        const char *q = strchr(p, '"');
        if (q) {
            size_t len = (size_t)(q - p);
            if (len < sizeof(ip_b)) {
                memcpy(ip_b, p, len);
                ip_b[len] = '\0';
            }
        }
    }
    if (!ip_b[0]) { fprintf(stderr, "no IP found\n"); ts_close(b); return 1; }
    fprintf(stderr, "B IP: %s\n", ip_b);

    /* B listens. */
    int listener = ts_listen(b, "tcp", ":4242");
    if (listener < 0) {
        char err[256];
        ts_errmsg(b, err, sizeof(err));
        fprintf(stderr, "ts_listen: %d: %s\n", listener, err);
        ts_close(b);
        return 1;
    }

    /* --- Server A (dialer) --- */
    int a = ts_new();
    if (a < 0) { fprintf(stderr, "ts_new A: %d\n", a); ts_listener_close(listener); ts_close(b); return 1; }
    ts_set_hostname(a, "rustscale-ffi-echo-a");
    ts_set_authkey(a, authkey);
    ts_set_ephemeral(a, 1);

    rc = ts_up(a);
    if (rc != 0) {
        char err[256];
        ts_errmsg(a, err, sizeof(err));
        fprintf(stderr, "ts_up A: %d: %s\n", rc, err);
        ts_close(a); ts_listener_close(listener); ts_close(b);
        return 1;
    }

    /* Wait for A to see B. */
    int found_peer = 0;
    for (int i = 0; i < 120; i++) {
        char st[4096];
        int n = ts_status_json(a, st, sizeof(st));
        if (n > 0) {
            st[n] = '\0';
            if (strstr(st, "\"peer_count\":") && strstr(st, "\"peer_count\":0") == NULL) {
                /* peer_count is not 0 */
                char *pp = strstr(st, "\"peer_count\":");
                if (pp) {
                    int pc = atoi(pp + strlen("\"peer_count\":"));
                    if (pc > 0) { found_peer = 1; break; }
                }
            }
        }
        SLEEP_MS(500);
    }
    if (!found_peer) { fprintf(stderr, "A never saw B\n"); ts_close(a); ts_listener_close(listener); ts_close(b); return 1; }

    /* A dials B. */
    char dial_addr[128];
    snprintf(dial_addr, sizeof(dial_addr), "%s:4242", ip_b);
    int conn_a = ts_dial(a, "tcp", dial_addr);
    if (conn_a < 0) {
        char err[256];
        ts_errmsg(a, err, sizeof(err));
        fprintf(stderr, "ts_dial: %d: %s\n", conn_a, err);
        ts_close(a); ts_listener_close(listener); ts_close(b);
        return 1;
    }

    /* B accepts. */
    int conn_b = ts_accept(listener);
    if (conn_b < 0) { fprintf(stderr, "ts_accept: %d\n", conn_b); ts_conn_close(conn_a); ts_close(a); ts_listener_close(listener); ts_close(b); return 1; }

    /* A writes. */
    const char *msg = "hello ffi";
    int w = ts_conn_write(conn_a, msg, (int)strlen(msg));
    if (w < 0) { fprintf(stderr, "write: %d\n", w); goto cleanup; }
    fprintf(stderr, "A sent: %s (%d bytes)\n", msg, w);

    /* B reads. */
    char rbuf[64] = {0};
    int r = ts_conn_read(conn_b, rbuf, sizeof(rbuf));
    if (r < 0) { fprintf(stderr, "read: %d\n", r); goto cleanup; }
    fprintf(stderr, "B recv: %.*s (%d bytes)\n", r, rbuf, r);

    /* B echoes. */
    w = ts_conn_write(conn_b, rbuf, r);
    if (w < 0) { fprintf(stderr, "echo write: %d\n", w); goto cleanup; }

    /* A reads echo. */
    r = ts_conn_read(conn_a, rbuf, sizeof(rbuf));
    if (r < 0) { fprintf(stderr, "echo read: %d\n", r); goto cleanup; }
    fprintf(stderr, "A recv: %.*s (%d bytes)\n", r, rbuf, r);

    printf("OK\n");

cleanup:
    ts_conn_close(conn_a);
    ts_conn_close(conn_b);
    ts_listener_close(listener);
    ts_close(a);
    ts_close(b);
    return 0;
}
