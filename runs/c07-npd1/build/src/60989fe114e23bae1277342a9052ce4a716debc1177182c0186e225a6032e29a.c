static unsigned sample(int missing) {
    unsigned *p = missing ? 0 : &live;
    /* target remains in the same function */
    return read_required(p);
}
