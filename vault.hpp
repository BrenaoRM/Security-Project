#ifndef VAULT_HPP
#define VAULT_HPP

#include <cstdint>
#include <string>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#include <wincrypt.h>
#endif

static constexpr const char VAULT_FILE_NAME[] = "vault.dat";
static constexpr const char VAULT_MAGIC[] = "PWV1";
static constexpr uint8_t VAULT_VERSION = 1;
static constexpr size_t SALT_SIZE = 16;
static constexpr size_t IV_SIZE = 16;
static constexpr size_t KEY_SIZE = 32;
static constexpr size_t HMAC_SIZE = 32;
static constexpr uint32_t PBKDF2_ITERATIONS = 100000;
static constexpr size_t MAX_FIELD_LENGTH = 256;

void secure_zero(void* ptr, size_t len);

class VaultEntry {
public:
    std::string site;
    std::string username;
    std::string password;

    void serialize(std::vector<uint8_t>& output) const;
    static bool deserialize(const uint8_t*& data, size_t& left, VaultEntry& entry);

private:
    static void appendUint16(std::vector<uint8_t>& output, uint16_t value);
    static void appendString(std::vector<uint8_t>& output, const std::string& value);
    static bool readString(const uint8_t*& data, size_t& left, std::string& output);
};

class Vault {
public:
    std::vector<VaultEntry> entries;

    void print() const;
    void addEntry(const VaultEntry& entry);
    bool removeEntry(size_t index);
    std::vector<uint8_t> serialize() const;
    static bool deserialize(const std::vector<uint8_t>& data, Vault& vault);
};

class CryptoEngine {
public:
    static bool fillRandom(uint8_t* buffer, size_t size);
    static void sha256(const uint8_t* data, size_t len, uint8_t hash[32]);
    static void hmacSha256(const uint8_t* key, size_t keyLen,
                           const uint8_t* data, size_t dataLen,
                           uint8_t out[32]);
    static void pbkdf2HmacSha256(const uint8_t* password, size_t passwordLen,
                                 const uint8_t* salt, size_t saltLen,
                                 uint32_t iterations, uint8_t* output, size_t outputLen);
    static bool aesCbcEncrypt(const uint8_t* key, size_t keyLen,
                              const uint8_t* iv, const uint8_t* plaintext,
                              size_t plaintextLen, std::vector<uint8_t>& ciphertext);
    static bool aesCbcDecrypt(const uint8_t* key, size_t keyLen,
                              const uint8_t* iv, const uint8_t* ciphertext,
                              size_t ciphertextLen, std::vector<uint8_t>& plaintext);

private:
    static bool aesCbcCrypt(const uint8_t* key, size_t keyLen,
                           const uint8_t* iv, uint8_t* buffer,
                           DWORD& bufferLen, DWORD maxLen, BOOL encrypt);
    static bool aesKeyFromBytes(HCRYPTPROV hProv, const uint8_t* key, size_t keyLen, HCRYPTKEY& hKey);
};

class VaultFile {
public:
    struct Header {
        char magic[4];
        uint8_t version;
        uint8_t salt[SALT_SIZE];
        uint8_t iv[IV_SIZE];
        uint32_t ciphertextLen;
    };

    static bool exists();
    static bool save(const Vault& vault, const std::string& password);
    static bool load(const std::string& password, Vault& vault);
};

bool readPassword(std::string& output, const char* prompt);
bool readLine(std::string& output, const char* prompt);

#endif // VAULT_HPP
