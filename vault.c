#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <inttypes.h>
#include <conio.h>
#ifdef _WIN32
#include <windows.h>
#include <wincrypt.h>
#pragma comment(lib, "advapi32.lib")
#endif

#define VAULT_FILE_NAME "vault.dat"
#define VAULT_MAGIC "PWV1"
#define VAULT_VERSION 1
#define SALT_SIZE 16
#define IV_SIZE 16
#define KEY_SIZE 32
#define HMAC_SIZE 32
#define PBKDF2_ITERATIONS 100000
#define MAX_ENTRIES 100
#define MAX_FIELD 64

typedef struct {
    char site[MAX_FIELD];
    char username[MAX_FIELD];
    char password[MAX_FIELD];
} Entry;

typedef struct {
    uint8_t magic[4];
    uint8_t version;
    uint8_t salt[SALT_SIZE];
    uint8_t iv[IV_SIZE];
    uint32_t ciphertext_len;
} VaultHeader;

typedef struct {
    Entry entries[MAX_ENTRIES];
    uint32_t count;
} Vault;

static void secure_zero(void* ptr, size_t len) {
    volatile uint8_t* p = (volatile uint8_t*)ptr;
    while (len--) {
        *p++ = 0;
    }
}

static bool os_random_bytes(uint8_t* buffer, size_t size) {
#ifdef _WIN32
    HCRYPTPROV provider = 0;
    if (!CryptAcquireContext(&provider, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        return false;
    }
    BOOL ok = CryptGenRandom(provider, (DWORD)size, buffer);
    CryptReleaseContext(provider, 0);
    return ok != 0;
#else
    FILE* fp = fopen("/dev/urandom", "rb");
    if (!fp) return false;
    size_t read = fread(buffer, 1, size, fp);
    fclose(fp);
    return read == size;
#endif
}

/* Minimal SHA-256 implementation */
#define ROTRIGHT(word,bits) (((word) >> (bits)) | ((word) << (32-(bits))))
#define CH(x,y,z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x) (ROTRIGHT(x,2) ^ ROTRIGHT(x,13) ^ ROTRIGHT(x,22))
#define EP1(x) (ROTRIGHT(x,6) ^ ROTRIGHT(x,11) ^ ROTRIGHT(x,25))
#define SIG0(x) (ROTRIGHT(x,7) ^ ROTRIGHT(x,18) ^ ((x) >> 3))
#define SIG1(x) (ROTRIGHT(x,17) ^ ROTRIGHT(x,19) ^ ((x) >> 10))

static const uint32_t k[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

static void sha256_transform(uint32_t state[8], const uint8_t data[64]) {
    uint32_t a, b, c, d, e, f, g, h, t1, t2;
    uint32_t m[64];
    for (int i = 0; i < 16; ++i) {
        m[i] = (uint32_t)data[i * 4] << 24 | (uint32_t)data[i * 4 + 1] << 16 |
               (uint32_t)data[i * 4 + 2] << 8 | (uint32_t)data[i * 4 + 3];
    }
    for (int i = 16; i < 64; ++i) {
        m[i] = SIG1(m[i-2]) + m[i-7] + SIG0(m[i-15]) + m[i-16];
    }
    a = state[0]; b = state[1]; c = state[2]; d = state[3];
    e = state[4]; f = state[5]; g = state[6]; h = state[7];
    for (int i = 0; i < 64; ++i) {
        t1 = h + EP1(e) + CH(e,f,g) + k[i] + m[i];
        t2 = EP0(a) + MAJ(a,b,c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }
    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
    state[5] += f;
    state[6] += g;
    state[7] += h;
}

static void sha256(const uint8_t* data, size_t len, uint8_t hash[32]) {
    uint32_t state[8] = {
        0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
        0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19
    };
    uint8_t block[64];
    uint64_t bitlen = len * 8ULL;
    size_t rem = len;
    const uint8_t* ptr = data;
    while (rem >= 64) {
        sha256_transform(state, ptr);
        ptr += 64;
        rem -= 64;
    }
    memset(block, 0, sizeof(block));
    memcpy(block, ptr, rem);
    block[rem] = 0x80;
    if (rem >= 56) {
        sha256_transform(state, block);
        memset(block, 0, sizeof(block));
    }
    block[56] = (uint8_t)(bitlen >> 56);
    block[57] = (uint8_t)(bitlen >> 48);
    block[58] = (uint8_t)(bitlen >> 40);
    block[59] = (uint8_t)(bitlen >> 32);
    block[60] = (uint8_t)(bitlen >> 24);
    block[61] = (uint8_t)(bitlen >> 16);
    block[62] = (uint8_t)(bitlen >> 8);
    block[63] = (uint8_t)(bitlen);
    sha256_transform(state, block);
    for (int i = 0; i < 8; ++i) {
        hash[i * 4]     = (uint8_t)(state[i] >> 24);
        hash[i * 4 + 1] = (uint8_t)(state[i] >> 16);
        hash[i * 4 + 2] = (uint8_t)(state[i] >> 8);
        hash[i * 4 + 3] = (uint8_t)(state[i]);
    }
}

static void hmac_sha256(const uint8_t* key, size_t key_len,
                        const uint8_t* data, size_t data_len,
                        uint8_t out[32]) {
    uint8_t k_ipad[64];
    uint8_t k_opad[64];
    uint8_t tk[32];
    if (key_len > 64) {
        sha256(key, key_len, tk);
        key = tk;
        key_len = 32;
    }
    memset(k_ipad, 0, sizeof(k_ipad));
    memset(k_opad, 0, sizeof(k_opad));
    memcpy(k_ipad, key, key_len);
    memcpy(k_opad, key, key_len);
    for (int i = 0; i < 64; ++i) {
        k_ipad[i] ^= 0x36;
        k_opad[i] ^= 0x5c;
    }
    uint8_t inner_hash[32];
    uint8_t buffer[64 + data_len];
    memcpy(buffer, k_ipad, 64);
    memcpy(buffer + 64, data, data_len);
    sha256(buffer, 64 + data_len, inner_hash);
    memcpy(buffer, k_opad, 64);
    memcpy(buffer + 64, inner_hash, 32);
    sha256(buffer, 64 + 32, out);
    secure_zero(tk, sizeof(tk));
    secure_zero(k_ipad, sizeof(k_ipad));
    secure_zero(k_opad, sizeof(k_opad));
    secure_zero(inner_hash, sizeof(inner_hash));
    secure_zero(buffer, sizeof(buffer));
}

static void pbkdf2_hmac_sha256(const uint8_t* password, size_t password_len,
                               const uint8_t* salt, size_t salt_len,
                               uint32_t iterations, uint8_t* output, size_t output_len) {
    uint8_t block[64 + 4];
    uint8_t u[32];
    uint8_t t[32];
    uint32_t blocks = (output_len + 31) / 32;
    for (uint32_t i = 1; i <= blocks; ++i) {
        memcpy(block, salt, salt_len);
        block[salt_len + 0] = (uint8_t)(i >> 24);
        block[salt_len + 1] = (uint8_t)(i >> 16);
        block[salt_len + 2] = (uint8_t)(i >> 8);
        block[salt_len + 3] = (uint8_t)(i);
        hmac_sha256(password, password_len, block, salt_len + 4, u);
        memcpy(t, u, 32);
        for (uint32_t j = 1; j < iterations; ++j) {
            hmac_sha256(password, password_len, u, 32, u);
            for (int k = 0; k < 32; ++k) {
                t[k] ^= u[k];
            }
        }
        size_t offset = (i - 1) * 32;
        size_t to_copy = output_len - offset;
        if (to_copy > 32) to_copy = 32;
        memcpy(output + offset, t, to_copy);
    }
    secure_zero(block, sizeof(block));
    secure_zero(u, sizeof(u));
    secure_zero(t, sizeof(t));
}

/* Minimal AES-128 / AES-256 implementation (CBC) */
static void xor_block(uint8_t* dest, const uint8_t* a, const uint8_t* b) {
    for (int i = 0; i < 16; ++i) dest[i] = a[i] ^ b[i];
}

static void pkcs7_pad(uint8_t* buffer, size_t data_len, size_t block_size) {
    uint8_t pad = (uint8_t)(block_size - data_len);
    for (size_t i = data_len; i < block_size; ++i) buffer[i] = pad;
}

static bool pkcs7_unpad(uint8_t* buffer, size_t* data_len) {
    if (*data_len == 0) return false;
    uint8_t pad = buffer[*data_len - 1];
    if (pad == 0 || pad > 16) return false;
    for (size_t i = *data_len - pad; i < *data_len; ++i) {
        if (buffer[i] != pad) return false;
    }
    *data_len -= pad;
    return true;
}

/* Basic AES implementation adapted from public domain tiny-AES-c, only for block encryption/decryption */
static const uint8_t sbox[256] = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

static uint8_t xtime(uint8_t x) {
    return (uint8_t)((x << 1) ^ ((x >> 7) * 0x1b));
}

static void sub_bytes(uint8_t state[16]) {
    for (int i = 0; i < 16; ++i) {
        state[i] = sbox[state[i]];
    }
}

static void shift_rows(uint8_t state[16]) {
    uint8_t temp[16];
    temp[0] = state[0]; temp[1] = state[5]; temp[2] = state[10]; temp[3] = state[15];
    temp[4] = state[4]; temp[5] = state[9]; temp[6] = state[14]; temp[7] = state[3];
    temp[8] = state[8]; temp[9] = state[13]; temp[10] = state[2]; temp[11] = state[7];
    temp[12] = state[12]; temp[13] = state[1]; temp[14] = state[6]; temp[15] = state[11];
    memcpy(state, temp, 16);
}

static void mix_columns(uint8_t state[16]) {
    for (int i = 0; i < 4; ++i) {
        int idx = i * 4;
        uint8_t a = state[idx];
        uint8_t b = state[idx + 1];
        uint8_t c = state[idx + 2];
        uint8_t d = state[idx + 3];
        uint8_t e = a ^ b ^ c ^ d;
        uint8_t xa = a ^ b;
        uint8_t xb = b ^ c;
        uint8_t xc = c ^ d;
        uint8_t xd = d ^ a;
        state[idx]     ^= e ^ xtime(xa);
        state[idx + 1] ^= e ^ xtime(xb);
        state[idx + 2] ^= e ^ xtime(xc);
        state[idx + 3] ^= e ^ xtime(xd);
    }
}

static void add_round_key(uint8_t state[16], const uint8_t* roundKey) {
    for (int i = 0; i < 16; ++i) state[i] ^= roundKey[i];
}

static void key_expansion(const uint8_t* key, uint8_t* roundKeys, size_t key_len) {
    int Nk = key_len / 4;
    int Nr = Nk + 6;
    int Nb = 4;
    memcpy(roundKeys, key, key_len);
    uint8_t temp[4];
    for (int i = Nk; i < Nb * (Nr + 1); ++i) {
        memcpy(temp, &roundKeys[(i - 1) * 4], 4);
        if (i % Nk == 0) {
            uint8_t t = temp[0];
            temp[0] = temp[1];
            temp[1] = temp[2];
            temp[2] = temp[3];
            temp[3] = t;
            temp[0] = sbox[temp[0]];
            temp[1] = sbox[temp[1]];
            temp[2] = sbox[temp[2]];
            temp[3] = sbox[temp[3]];
            temp[0] ^= (uint8_t)(0x01 << ((i / Nk) - 1));
        } else if (Nk > 6 && i % Nk == 4) {
            temp[0] = sbox[temp[0]];
            temp[1] = sbox[temp[1]];
            temp[2] = sbox[temp[2]];
            temp[3] = sbox[temp[3]];
        }
        for (int j = 0; j < 4; ++j) {
            roundKeys[i * 4 + j] = roundKeys[(i - Nk) * 4 + j] ^ temp[j];
        }
    }
}

static void aes_encrypt_block(uint8_t* block, const uint8_t* key, size_t key_len) {
    int Nk = key_len / 4;
    int Nr = Nk + 6;
    uint8_t roundKeys[240];
    key_expansion(key, roundKeys, key_len);
    add_round_key(block, roundKeys);
    for (int round = 1; round < Nr; ++round) {
        sub_bytes(block);
        shift_rows(block);
        mix_columns(block);
        add_round_key(block, roundKeys + round * 16);
    }
    sub_bytes(block);
    shift_rows(block);
    add_round_key(block, roundKeys + Nr * 16);
    secure_zero(roundKeys, sizeof(roundKeys));
}

static bool aes_key_from_bytes(const uint8_t* key, size_t key_len, HCRYPTPROV hProv, HCRYPTKEY* phKey) {
    if (key_len != 16 && key_len != 24 && key_len != 32) return false;
    BLOBHEADER header;
    header.bType = PLAINTEXTKEYBLOB;
    header.bVersion = CUR_BLOB_VERSION;
    header.reserved = 0;
    header.aiKeyAlg = (key_len == 16 ? CALG_AES_128 : key_len == 24 ? CALG_AES_192 : CALG_AES_256);
    DWORD blobSize = sizeof(header) + sizeof(DWORD) + (DWORD)key_len;
    uint8_t* blob = (uint8_t*)malloc(blobSize);
    if (!blob) return false;
    memcpy(blob, &header, sizeof(header));
    memcpy(blob + sizeof(header), &key_len, sizeof(DWORD));
    memcpy(blob + sizeof(header) + sizeof(DWORD), key, key_len);
    BOOL ok = CryptImportKey(hProv, blob, blobSize, 0, 0, phKey);
    secure_zero(blob, blobSize);
    free(blob);
    return ok != 0;
}

static bool aes_cbc_crypt(const uint8_t* key, size_t key_len,
                          const uint8_t* iv, uint8_t* buffer, DWORD* buffer_len,
                          DWORD max_len, BOOL encrypt) {
    HCRYPTPROV hProv = 0;
    HCRYPTKEY hKey = 0;
    BOOL result = FALSE;
    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        return false;
    }
    if (!aes_key_from_bytes(key, key_len, hProv, &hKey)) {
        CryptReleaseContext(hProv, 0);
        return false;
    }
    DWORD mode = CRYPT_MODE_CBC;
    if (!CryptSetKeyParam(hKey, KP_MODE, (BYTE*)&mode, 0)) {
        CryptDestroyKey(hKey);
        CryptReleaseContext(hProv, 0);
        return false;
    }
    if (!CryptSetKeyParam(hKey, KP_IV, (BYTE*)iv, 0)) {
        CryptDestroyKey(hKey);
        CryptReleaseContext(hProv, 0);
        return false;
    }
    if (encrypt) {
        result = CryptEncrypt(hKey, 0, TRUE, 0, buffer, buffer_len, max_len);
    } else {
        result = CryptDecrypt(hKey, 0, TRUE, 0, buffer, buffer_len);
    }
    CryptDestroyKey(hKey);
    CryptReleaseContext(hProv, 0);
    return result != 0;
}

static bool aes_cbc_encrypt(const uint8_t* key, size_t key_len,
                            const uint8_t* iv, const uint8_t* plaintext, size_t plaintext_len,
                            uint8_t* ciphertext, size_t* ciphertext_len) {
    DWORD max_len = (DWORD)(plaintext_len + 16);
    uint8_t* buffer = (uint8_t*)malloc(max_len);
    if (!buffer) return false;
    memcpy(buffer, plaintext, plaintext_len);
    DWORD len = (DWORD)plaintext_len;
    if (!aes_cbc_crypt(key, key_len, iv, buffer, &len, max_len, TRUE)) {
        secure_zero(buffer, max_len);
        free(buffer);
        return false;
    }
    memcpy(ciphertext, buffer, len);
    *ciphertext_len = len;
    secure_zero(buffer, max_len);
    free(buffer);
    return true;
}

static bool aes_cbc_decrypt(const uint8_t* key, size_t key_len,
                            const uint8_t* iv, const uint8_t* ciphertext, size_t ciphertext_len,
                            uint8_t* plaintext, size_t* plaintext_len) {
    if (ciphertext_len == 0 || ciphertext_len % 16 != 0) return false;
    uint8_t* buffer = (uint8_t*)malloc(ciphertext_len);
    if (!buffer) return false;
    memcpy(buffer, ciphertext, ciphertext_len);
    DWORD len = (DWORD)ciphertext_len;
    if (!aes_cbc_crypt(key, key_len, iv, buffer, &len, (DWORD)ciphertext_len, FALSE)) {
        secure_zero(buffer, ciphertext_len);
        free(buffer);
        return false;
    }
    memcpy(plaintext, buffer, len);
    *plaintext_len = len;
    secure_zero(buffer, ciphertext_len);
    free(buffer);
    return true;
}

static bool read_line(char* buffer, size_t size) {
    if (!fgets(buffer, (int)size, stdin)) return false;
    size_t len = strlen(buffer);
    if (len > 0 && buffer[len - 1] == '\n') buffer[len - 1] = '\0';
    return true;
}

static bool read_password(char* buffer, size_t size, const char* prompt) {
    printf("%s", prompt);
    size_t idx = 0;
    int ch;
    while ((ch = _getch()) != EOF && ch != '\r' && ch != '\n') {
        if (ch == 8 || ch == 127) {
            if (idx > 0) {
                idx--;
                printf("\b \b");
            }
        } else if (idx + 1 < size) {
            buffer[idx++] = (char)ch;
            printf("*");
        }
    }
    buffer[idx] = '\0';
    printf("\n");
    return true;
}

static void print_entries(const Vault* vault) {
    if (vault->count == 0) {
        printf("Nenhuma entrada registrada.\n");
        return;
    }
    for (uint32_t i = 0; i < vault->count; ++i) {
        printf("[%u] Site: %s | Usuário: %s | Senha: %s\n",
               i + 1,
               vault->entries[i].site,
               vault->entries[i].username,
               vault->entries[i].password);
    }
}

static bool save_vault(const Vault* vault, const char* password) {
    uint8_t salt[SALT_SIZE];
    uint8_t iv[IV_SIZE];
    uint8_t key_material[KEY_SIZE * 2];
    uint8_t enc_key[KEY_SIZE];
    uint8_t auth_key[KEY_SIZE];
    uint8_t plaintext[sizeof(Vault)];
    uint8_t ciphertext[sizeof(plaintext) + 16];
    uint8_t hmac[HMAC_SIZE];
    VaultHeader header;

    if (!os_random_bytes(salt, SALT_SIZE)) return false;
    if (!os_random_bytes(iv, IV_SIZE)) return false;
    pbkdf2_hmac_sha256((uint8_t*)password, strlen(password), salt, SALT_SIZE, PBKDF2_ITERATIONS, key_material, sizeof(key_material));
    memcpy(enc_key, key_material, KEY_SIZE);
    memcpy(auth_key, key_material + KEY_SIZE, KEY_SIZE);

    memcpy(plaintext, vault, sizeof(Vault));
    size_t ciphertext_len = 0;
    if (!aes_cbc_encrypt(enc_key, KEY_SIZE, iv, plaintext, sizeof(Vault), ciphertext, &ciphertext_len)) {
        secure_zero(key_material, sizeof(key_material));
        secure_zero(enc_key, sizeof(enc_key));
        secure_zero(auth_key, sizeof(auth_key));
        secure_zero(plaintext, sizeof(plaintext));
        return false;
    }
    hmac_sha256(auth_key, KEY_SIZE, ciphertext, ciphertext_len, hmac);
    memcpy(header.magic, VAULT_MAGIC, 4);
    header.version = VAULT_VERSION;
    memcpy(header.salt, salt, SALT_SIZE);
    memcpy(header.iv, iv, IV_SIZE);
    header.ciphertext_len = (uint32_t)ciphertext_len;

    FILE* fp = fopen(VAULT_FILE_NAME, "wb");
    if (!fp) return false;
    fwrite(&header, sizeof(header), 1, fp);
    fwrite(ciphertext, 1, ciphertext_len, fp);
    fwrite(hmac, HMAC_SIZE, 1, fp);
    fclose(fp);

    secure_zero(key_material, sizeof(key_material));
    secure_zero(enc_key, sizeof(enc_key));
    secure_zero(auth_key, sizeof(auth_key));
    secure_zero(plaintext, sizeof(plaintext));
    secure_zero(ciphertext, sizeof(ciphertext));
    secure_zero(hmac, sizeof(hmac));
    return true;
}

static bool load_vault(Vault* vault, const char* password) {
    uint8_t key_material[KEY_SIZE * 2];
    uint8_t enc_key[KEY_SIZE];
    uint8_t auth_key[KEY_SIZE];
    uint8_t hmac[HMAC_SIZE];
    uint8_t plaintext[sizeof(Vault)];
    VaultHeader header;

    FILE* fp = fopen(VAULT_FILE_NAME, "rb");
    if (!fp) return false;
    if (fread(&header, sizeof(header), 1, fp) != 1) { fclose(fp); return false; }
    if (memcmp(header.magic, VAULT_MAGIC, 4) != 0 || header.version != VAULT_VERSION) {
        fclose(fp);
        return false;
    }
    if (fread(hmac, HMAC_SIZE, 1, fp) != 1) { fclose(fp); return false; }
    uint8_t* ciphertext = malloc(header.ciphertext_len);
    if (!ciphertext) { fclose(fp); return false; }
    if (fread(ciphertext, 1, header.ciphertext_len, fp) != header.ciphertext_len) {
        free(ciphertext);
        fclose(fp);
        return false;
    }
    fclose(fp);
    pbkdf2_hmac_sha256((uint8_t*)password, strlen(password), header.salt, SALT_SIZE, PBKDF2_ITERATIONS, key_material, sizeof(key_material));
    memcpy(enc_key, key_material, KEY_SIZE);
    memcpy(auth_key, key_material + KEY_SIZE, KEY_SIZE);
    uint8_t computed_hmac[HMAC_SIZE];
    hmac_sha256(auth_key, KEY_SIZE, ciphertext, header.ciphertext_len, computed_hmac);
    if (memcmp(hmac, computed_hmac, HMAC_SIZE) != 0) {
        free(ciphertext);
        return false;
    }
    size_t plaintext_len = 0;
    if (!aes_cbc_decrypt(enc_key, KEY_SIZE, header.iv, ciphertext, header.ciphertext_len, plaintext, &plaintext_len)) {
        free(ciphertext);
        return false;
    }
    if (plaintext_len != sizeof(Vault)) {
        free(ciphertext);
        return false;
    }
    memcpy(vault, plaintext, sizeof(Vault));
    free(ciphertext);
    secure_zero(key_material, sizeof(key_material));
    secure_zero(enc_key, sizeof(enc_key));
    secure_zero(auth_key, sizeof(auth_key));
    secure_zero(plaintext, sizeof(plaintext));
    secure_zero(computed_hmac, sizeof(computed_hmac));
    return true;
}

int main(void) {
    Vault vault = {0};
    char master_password[128] = {0};
    char confirm_password[128] = {0};
    bool file_exists = false;
    FILE* fp = fopen(VAULT_FILE_NAME, "rb");
    if (fp) { file_exists = true; fclose(fp); }

    if (file_exists) {
        if (!read_password(master_password, sizeof(master_password), "Digite a Senha Mestra: ")) {
            return 1;
        }
        if (!load_vault(&vault, master_password)) {
            printf("Senha incorreta ou arquivo de cofres inválido.\n");
            secure_zero(master_password, sizeof(master_password));
            return 1;
        }
        printf("Cofre carregado com sucesso.\n");
    } else {
        printf("Nenhum cofre encontrado. Vamos criar um novo cofre.\n");
        read_password(master_password, sizeof(master_password), "Defina uma nova Senha Mestra: ");
        read_password(confirm_password, sizeof(confirm_password), "Confirme a Senha Mestra: ");
        if (strcmp(master_password, confirm_password) != 0 || strlen(master_password) == 0) {
            printf("Senhas não conferem ou são inválidas.\n");
            secure_zero(master_password, sizeof(master_password));
            secure_zero(confirm_password, sizeof(confirm_password));
            return 1;
        }
        vault.count = 0;
        if (!save_vault(&vault, master_password)) {
            printf("Falha ao criar o arquivo do cofre.\n");
            secure_zero(master_password, sizeof(master_password));
            secure_zero(confirm_password, sizeof(confirm_password));
            return 1;
        }
        printf("Cofre criado com sucesso.\n");
        secure_zero(confirm_password, sizeof(confirm_password));
    }

    while (true) {
        printf("\nMenu:\n");
        printf("1. Listar entradas\n");
        printf("2. Adicionar entrada\n");
        printf("3. Remover entrada\n");
        printf("4. Salvar e sair\n");
        printf("Escolha: ");
        int option = getchar();
        while (getchar() != '\n');
        if (option == '1') {
            print_entries(&vault);
        } else if (option == '2') {
            if (vault.count >= MAX_ENTRIES) {
                printf("Máximo de entradas atingido.\n");
                continue;
            }
            printf("Site: "); read_line(vault.entries[vault.count].site, MAX_FIELD);
            printf("Usuário: "); read_line(vault.entries[vault.count].username, MAX_FIELD);
            printf("Senha: "); read_line(vault.entries[vault.count].password, MAX_FIELD);
            vault.count++;
            printf("Entrada adicionada.\n");
        } else if (option == '3') {
            if (vault.count == 0) {
                printf("Nenhuma entrada para remover.\n");
                continue;
            }
            print_entries(&vault);
            printf("Número da entrada a remover: ");
            char idx_str[16];
            read_line(idx_str, sizeof(idx_str));
            int idx = atoi(idx_str);
            if (idx < 1 || idx > (int)vault.count) {
                printf("Índice inválido.\n");
                continue;
            }
            for (uint32_t j = idx - 1; j + 1 < vault.count; ++j) {
                vault.entries[j] = vault.entries[j + 1];
            }
            vault.count--;
            printf("Entrada removida.\n");
        } else if (option == '4') {
            if (!save_vault(&vault, master_password)) {
                printf("Falha ao salvar o arquivo do cofre.\n");
                secure_zero(master_password, sizeof(master_password));
                return 1;
            }
            printf("Cofre salvo e encerrado.\n");
            break;
        } else {
            printf("Opção inválida.\n");
        }
    }

    secure_zero(&vault, sizeof(vault));
    secure_zero(master_password, sizeof(master_password));
    return 0;
}
