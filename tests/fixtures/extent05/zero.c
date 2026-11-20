static unsigned sample(void) {
    unsigned char buffer[8] = {0};
    return read_slice(buffer, 8, 0);
}
