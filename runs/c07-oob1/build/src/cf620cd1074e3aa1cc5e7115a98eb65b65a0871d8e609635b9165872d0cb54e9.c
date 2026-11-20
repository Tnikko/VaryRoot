unsigned sample(void) {
    unsigned data[8] = {0};
    unsigned i = 1;
    return read_span(data, i, 4);
}
