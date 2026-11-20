int sample(int mode) {
    ldapconninfo connection; connection.ld = 0;
    if (mode != 2 && mode != 3) return -1;
    normal = mode == 2;
    hits = calls = 0;
    return ldap_recv_slice(&connection, 0, 0);
}
int call_count(void) { return calls; }
int hit_count(void) { return hits; }
int at_rc(int j) { return log_rc[j]; }
int at_null(int j) { return log_null[j]; }
int at_index(int j) { return log_index[j]; }
int at_owner(int j) { return log_owner[j]; }
