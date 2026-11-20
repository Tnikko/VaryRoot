static unsigned sample(int missing) {
    unsigned *p = missing ? 0 : &live;
    if (!p) p = &live;
    return read_required(p);
}
