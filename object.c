int object_write(const void *data, size_t size, char *hash_out) {
    unsigned char hash[32];
    char header[64];

    // Create header: "blob <size>\0"
    int header_len = sprintf(header, "blob %zu", size) + 1;

    // Combine header + data
    size_t total_size = header_len + size;
    char *buffer = malloc(total_size);
    if (!buffer) return -1;

    memcpy(buffer, header, header_len);
    memcpy(buffer + header_len, data, size);

    // Compute SHA-256
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, buffer, total_size);
    EVP_DigestFinal_ex(ctx, hash, NULL);
    EVP_MD_CTX_free(ctx);

    // Convert hash → hex string
    for (int i = 0; i < 32; i++)
        sprintf(hash_out + i * 2, "%02x", hash[i]);
    hash_out[64] = '\0';

    // Create directories
    mkdir(".pes", 0755);
    mkdir(".pes/objects", 0755);

    char dir[256];
    snprintf(dir, sizeof(dir), ".pes/objects/%.2s", hash_out);
    mkdir(dir, 0755);

    // File path
    char path[256];
    snprintf(path, sizeof(path), "%s/%s", dir, hash_out + 2);

    // Write file
    FILE *f = fopen(path, "wb");
    if (!f) {
        free(buffer);
        return -1;
    }

    fwrite(buffer, 1, total_size, f);
    fclose(f);

    free(buffer);
    return 0;
}
