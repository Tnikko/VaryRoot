int sample(int selected_mode) {
    ldapconninfo connection;
    if (selected_mode < 1 || selected_mode > 4)
        return -1;
    connection.ld = 0;
    mode = selected_mode;
    calls = hits = reads = violation_seen = 0;
    return ldap_recv_slice(&connection, 0, 0);
}
