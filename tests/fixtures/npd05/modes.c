static unsigned sample(int missing) {
    unsigned *p = missing ? 0 : &live;
    if (missing == 1) return 0;
    if (!p) p = &live;
    return read_required(p);
}
