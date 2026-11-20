unsigned sample(void) {
    unsigned data[8] = {0};
    unsigned i = 3;
    if (i >= 2) i = 1;
    /* target remains in the same function */
    return data[i];
}
