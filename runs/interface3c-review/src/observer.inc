/* The two admitted fixtures provide one owned array or an end-of-stream result. */
static struct berval items[2] = {{1, "v"}, {0, 0}};
static int normal, calls, hits;
static int log_rc[4], log_null[4], log_index[4], log_owner[4];
int ldap_get_attribute_ber(LDAP *ld, LDAPMessage *ent, BerElement *ber,
                           struct berval *name, struct berval **values) {
    ++calls;
    if (normal && calls == 1) {
        name->bv_val = "a";
        name->bv_len = 1;
        *values = items;
        return LDAP_SUCCESS;
    }
    *values = 0;
    return LDAP_NO_SUCH_ATTRIBUTE;
}
static char *observe(int rc, struct berval *owner, int index) {
    if (hits >= 4 || owner != items || index < 0 || index > 1) __builtin_trap();
    log_rc[hits] = rc;
    log_null[hits] = owner == 0;
    log_index[hits] = index;
    log_owner[hits] = owner == items;
    ++hits;
    /* Shadow value for the owned two-element fixture, with no indexed access. */
    return index == 0 ? "v" : 0;
}
