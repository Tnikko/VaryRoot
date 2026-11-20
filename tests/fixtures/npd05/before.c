static unsigned sample(int missing) {
    unsigned *p = missing ? 0 : &live;
    return read_required(p);
}
