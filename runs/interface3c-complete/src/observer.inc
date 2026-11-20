/* Finite-domain substitute for the independently reviewed OpenLDAP return slot. */
static struct berval items[2] = {{1, "v"}, {0, 0}};
static int mode, calls, hits, reads, violation_seen;
static int call_rc_log[4], call_null_log[4], call_attribute_log[4];
static int call_after_violation_log[4];
static int hit_rc_log[8], hit_null_log[8], hit_index_log[8];
static int hit_owner_log[8], hit_kind_log[8], hit_value_log[8];
static int hit_after_violation_log[8];

int ldap_get_attribute_ber(LDAP *ld, LDAPMessage *ent, BerElement *ber,
                           struct berval *name, struct berval **values) {
    int ordinal = ++calls;
    int success_with_array = !violation_seen &&
                             ((mode == 2 && ordinal == 1) ||
                              (mode == 4 && ordinal == 2));
    int success_with_null = !violation_seen &&
                            ((mode == 1 && ordinal == 1) ||
                             (mode == 4 && ordinal == 1));
    int result;
    if (ordinal > 4)
        __builtin_trap();
    if (success_with_array || success_with_null) {
        name->bv_val = ordinal == 2 ? "b" : "a";
        name->bv_len = 1;
        *values = success_with_array ? items : 0;
        result = LDAP_SUCCESS;
    }
    else {
        name->bv_val = 0;
        name->bv_len = 0;
        *values = 0;
        result = LDAP_NO_SUCH_ATTRIBUTE;
    }
    call_after_violation_log[ordinal - 1] = violation_seen;
    call_rc_log[ordinal - 1] = result;
    call_null_log[ordinal - 1] = *values == 0;
    call_attribute_log[ordinal - 1] = result == LDAP_SUCCESS ? ordinal : 0;
    return result;
}

/* The call replaces exactly one mapped expression. Invalid paths stop before indexing. */
static char *observe(int rc, struct berval *owner, int index) {
    int slot = hits++;
    char *value;
    if (slot >= 8)
        __builtin_trap();
    hit_rc_log[slot] = rc;
    hit_null_log[slot] = owner == 0;
    hit_index_log[slot] = index;
    hit_owner_log[slot] = owner == items;
    hit_after_violation_log[slot] = violation_seen;
    if (owner == 0) {
        hit_kind_log[slot] = 1;
        hit_value_log[slot] = -1;
        violation_seen = 1;
        return 0;
    }
    if (owner != items || index < 0 || index >= 2)
        __builtin_trap();
    value = owner[index].bv_val;
    hit_kind_log[slot] = 2;
    hit_value_log[slot] = value != 0;
    ++reads;
    return value;
}

int call_count(void) { return calls; }
int hit_count(void) { return hits; }
int read_count(void) { return reads; }
int at_call_rc(int j) { return call_rc_log[j]; }
int at_call_after_violation(int j) { return call_after_violation_log[j]; }
int at_call_null(int j) { return call_null_log[j]; }
int at_call_attribute(int j) { return call_attribute_log[j]; }
int at_hit_rc(int j) { return hit_rc_log[j]; }
int at_hit_null(int j) { return hit_null_log[j]; }
int at_hit_index(int j) { return hit_index_log[j]; }
int at_hit_owner(int j) { return hit_owner_log[j]; }
int at_hit_kind(int j) { return hit_kind_log[j]; }
int at_hit_value(int j) { return hit_value_log[j]; }
int at_hit_after_violation(int j) { return hit_after_violation_log[j]; }
