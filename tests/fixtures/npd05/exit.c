static unsigned sample(int missing) {
    unsigned *p = missing ? 0 : &live;
    if (!p) return 0;
    return read_required(p);
}
