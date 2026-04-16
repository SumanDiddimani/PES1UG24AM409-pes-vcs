#include <stdio.h>
#include<stddef.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <sys/stat.h>
#include <unistd.h>

// =======================
// OBJECT WRITE
// =======================
int object_write(const void *data, size_t size, char *hash_out) {
    // 1. Create header
    char header[64];
    int header_len = snprintf(header, sizeof(header), "blob %zu", size) + 1;

    // 2. Combine header + data
    size_t total_size = header_len + size;
    unsigned char *buffer = malloc(total_size);
    if (!buffer) return -1;

    memcpy(buffer, header, header_len);
    memcpy(buffer + header_len, data, size);

    // 3. Compute SHA-256 using EVP
    unsigned char hash[32];
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();

    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, buffer, total_size);
    EVP_DigestFinal_ex(ctx, hash, NULL);

    EVP_MD_CTX_free(ctx);

    // 4. Convert hash → hex string
    for (int i = 0; i < 32; i++) {
        sprintf(hash_out + i * 2, "%02x", hash[i]);
    }
    hash_out[64] = '\0';

    // 5. Create directories
    mkdir(".pes", 0755);
    mkdir(".pes/objects", 0755);

    char dir[256];
    snprintf(dir, sizeof(dir), ".pes/objects/%.2s", hash_out);
    mkdir(dir, 0755);

    // 6. File path
    char path[256];
    snprintf(path, sizeof(path), "%s/%s", dir, hash_out + 2);

    // 7. Write using temp file (ATOMIC)
    char temp_path[256];
    snprintf(temp_path, sizeof(temp_path), "%s.tmp", path);

    FILE *f = fopen(temp_path, "wb");
    if (!f) {
        free(buffer);
        return -1;
    }

    fwrite(buffer, 1, total_size, f);
    fclose(f);

    rename(temp_path, path);

    free(buffer);
    return 0;
}

// =======================
// OBJECT READ
// =======================
int object_read(const char *hash, void **data_out, size_t *size_out) {
    // 1. Construct file path
    char path[256];
    snprintf(path, sizeof(path), ".pes/objects/%.2s/%s", hash, hash + 2);

    FILE *f = fopen(path, "rb");
    if (!f) return -1;

    // 2. Get file size
    fseek(f, 0, SEEK_END);
    long file_size = ftell(f);
    rewind(f);

    unsigned char *buffer = malloc(file_size);
    if (!buffer) {
        fclose(f);
        return -1;
    }

    fread(buffer, 1, file_size, f);
    fclose(f);

    // 3. Find header end (\0)
    char *null_pos = memchr(buffer, '\0', file_size);
    if (!null_pos) {
        free(buffer);
        return -1;
    }

    size_t header_len = null_pos - (char *)buffer + 1;
    *size_out = file_size - header_len;

    // 4. Extract data
    *data_out = malloc(*size_out);
    if (!(*data_out)) {
        free(buffer);
        return -1;
    }

    memcpy(*data_out, buffer + header_len, *size_out);

    // 5. Verify hash
    unsigned char hash_calc[32];
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();

    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, buffer, file_size);
    EVP_DigestFinal_ex(ctx, hash_calc, NULL);

    EVP_MD_CTX_free(ctx);

    char hash_hex[65];
    for (int i = 0; i < 32; i++) {
        sprintf(hash_hex + i * 2, "%02x", hash_calc[i]);
    }
    hash_hex[64] = '\0';

    if (strcmp(hash, hash_hex) != 0) {
        free(buffer);
        free(*data_out);
        return -1;
    }

    free(buffer);
    return 0;
}
