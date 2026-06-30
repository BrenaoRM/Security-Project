#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iostream>
#include <limits>
#include <string>
#include <vector>

#ifdef _WIN32
#include <conio.h>
#include <windows.h>
#include <wincrypt.h>
#pragma comment(lib, "advapi32.lib")
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

static void secure_zero(void* ptr, size_t len) {
    volatile uint8_t* p = static_cast<volatile uint8_t*>(ptr);
    while (len--) {
        *p++ = 0;
    }
}

class VaultEntry {
public:
    std::string site;
    std::string username;
    std::string password;

    void serialize(std::vector<uint8_t>& output) const {
        appendString(output, site);
        appendString(output, username);
        appendString(output, password);
    }

    static bool deserialize(const uint8_t*& data, size_t& left, VaultEntry& entry) {
        return readString(data, left, entry.site)
            && readString(data, left, entry.username)
            && readString(data, left, entry.password);
    }

private:
    static void appendUint16(std::vector<uint8_t>& output, uint16_t value) {
        output.push_back(static_cast<uint8_t>(value & 0xFF));
        output.push_back(static_cast<uint8_t>((value >> 8) & 0xFF));
    }

    static void appendString(std::vector<uint8_t>& output, const std::string& value) {
        if (value.size() > std::numeric_limits<uint16_t>::max()) {
            return;
        }
        appendUint16(output, static_cast<uint16_t>(value.size()));
        output.insert(output.end(), value.begin(), value.end());
    }

    static bool readString(const uint8_t*& data, size_t& left, std::string& output) {
        if (left < sizeof(uint16_t)) {
            return false;
        }
        uint16_t length = static_cast<uint16_t>(data[0] | (data[1] << 8));
        data += sizeof(uint16_t);
        left -= sizeof(uint16_t);
        if (left < length) {
            return false;
        }
        output.assign(reinterpret_cast<const char*>(data), length);
        data += length;
        left -= length;
        return true;
    }
};

class Vault {
public:
    std::vector<VaultEntry> entries;

    void print() const {
        if (entries.empty()) {
            std::cout << "Nenhuma entrada registrada." << std::endl;
            return;
        }
        for (size_t i = 0; i < entries.size(); ++i) {
            const auto& entry = entries[i];
            std::cout << "[" << (i + 1) << "] Site: " << entry.site
                      << " | Usuário: " << entry.username
                      << " | Senha: " << entry.password << '\n';
        }
    }

    void addEntry(const VaultEntry& entry) {
        entries.push_back(entry);
    }

    bool removeEntry(size_t index) {
        if (index >= entries.size()) {
            return false;
        }
        entries.erase(entries.begin() + index);
        return true;
    }

    std::vector<uint8_t> serialize() const {
        std::vector<uint8_t> output;
        output.reserve(4 + entries.size() * 64);
        auto appendUint32 = [&](uint32_t value) {
            output.push_back(static_cast<uint8_t>(value & 0xFF));
            output.push_back(static_cast<uint8_t>((value >> 8) & 0xFF));
            output.push_back(static_cast<uint8_t>((value >> 16) & 0xFF));
            output.push_back(static_cast<uint8_t>((value >> 24) & 0xFF));
        };
        appendUint32(static_cast<uint32_t>(entries.size()));
        for (const auto& entry : entries) {
            entry.serialize(output);
        }
        return output;
    }

    static bool deserialize(const std::vector<uint8_t>& data, Vault& vault) {
        vault.entries.clear();
        if (data.size() < 4) {
            return false;
        }
        const uint8_t* ptr = data.data();
        size_t left = data.size();
        uint32_t count = ptr[0] | (ptr[1] << 8) | (ptr[2] << 16) | (ptr[3] << 24);
        ptr += 4;
        left -= 4;
        for (uint32_t i = 0; i < count; ++i) {
            VaultEntry entry;
            if (!VaultEntry::deserialize(ptr, left, entry)) {
                return false;
            }
            if (entry.site.size() > MAX_FIELD_LENGTH || entry.username.size() > MAX_FIELD_LENGTH || entry.password.size() > MAX_FIELD_LENGTH) {
                return false;
            }
            vault.entries.push_back(std::move(entry));
        }
        return left == 0;
    }
};

class CryptoEngine {
public:
    static bool fillRandom(uint8_t* buffer, size_t size) {
#ifdef _WIN32
        HCRYPTPROV provider = 0;
        if (!CryptAcquireContext(&provider, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
            return false;
        }
        BOOL ok = CryptGenRandom(provider, static_cast<DWORD>(size), buffer);
        CryptReleaseContext(provider, 0);
        return ok != 0;
#else
        std::ifstream urandom("/dev/urandom", std::ios::binary);
        if (!urandom) {
            return false;
        }
        urandom.read(reinterpret_cast<char*>(buffer), size);
        return urandom.gcount() == static_cast<std::streamsize>(size);
#endif
    }

    static void sha256(const uint8_t* data, size_t len, uint8_t hash[32]) {
        static const uint32_t k[64] = {
            0x428a2f98u,0x71374491u,0xb5c0fbcfu,0xe9b5dba5u,0x3956c25bu,0x59f111f1u,0x923f82a4u,0xab1c5ed5u,
            0xd807aa98u,0x12835b01u,0x243185beu,0x550c7dc3u,0x72be5d74u,0x80deb1feu,0x9bdc06a7u,0xc19bf174u,
            0xe49b69c1u,0xefbe4786u,0x0fc19dc6u,0x240ca1ccu,0x2de92c6fu,0x4a7484aau,0x5cb0a9dcu,0x76f988dau,
            0x983e5152u,0xa831c66du,0xb00327c8u,0xbf597fc7u,0xc6e00bf3u,0xd5a79147u,0x06ca6351u,0x14292967u,
            0x27b70a85u,0x2e1b2138u,0x4d2c6dfcu,0x53380d13u,0x650a7354u,0x766a0abbu,0x81c2c92eu,0x92722c85u,
            0xa2bfe8a1u,0xa81a664bu,0xc24b8b70u,0xc76c51a3u,0xd192e819u,0xd6990624u,0xf40e3585u,0x106aa070u,
            0x19a4c116u,0x1e376c08u,0x2748774cu,0x34b0bcb5u,0x391c0cb3u,0x4ed8aa4au,0x5b9cca4fu,0x682e6ff3u,
            0x748f82eeu,0x78a5636fu,0x84c87814u,0x8cc70208u,0x90befffau,0xa4506cebu,0xbef9a3f7u,0xc67178f2u
        };
        auto rotr = [&](uint32_t x, unsigned bits) { return (x >> bits) | (x << (32 - bits)); };
        auto ch = [&](uint32_t x, uint32_t y, uint32_t z) { return (x & y) ^ (~x & z); };
        auto maj = [&](uint32_t x, uint32_t y, uint32_t z) { return (x & y) ^ (x & z) ^ (y & z); };
        auto bigSigma0 = [&](uint32_t x) { return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22); };
        auto bigSigma1 = [&](uint32_t x) { return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25); };
        auto smallSigma0 = [&](uint32_t x) { return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3); };
        auto smallSigma1 = [&](uint32_t x) { return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10); };

        uint32_t state[8] = {
            0x6a09e667u,0xbb67ae85u,0x3c6ef372u,0xa54ff53au,
            0x510e527fu,0x9b05688cu,0x1f83d9abu,0x5be0cd19u
        };
        size_t remaining = len;
        const uint8_t* current = data;
        uint8_t block[64] = {0};

        auto processBlock = [&](const uint8_t chunk[64]) {
            uint32_t w[64];
            for (int i = 0; i < 16; ++i) {
                w[i] = (uint32_t)chunk[i * 4] << 24 |
                       (uint32_t)chunk[i * 4 + 1] << 16 |
                       (uint32_t)chunk[i * 4 + 2] << 8 |
                       (uint32_t)chunk[i * 4 + 3];
            }
            for (int i = 16; i < 64; ++i) {
                w[i] = smallSigma1(w[i - 2]) + w[i - 7] + smallSigma0(w[i - 15]) + w[i - 16];
            }
            uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
            uint32_t e = state[4], f = state[5], g = state[6], h = state[7];
            for (int i = 0; i < 64; ++i) {
                uint32_t t1 = h + bigSigma1(e) + ch(e, f, g) + k[i] + w[i];
                uint32_t t2 = bigSigma0(a) + maj(a, b, c);
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
        };

        while (remaining >= 64) {
            processBlock(current);
            current += 64;
            remaining -= 64;
        }

        std::memset(block, 0, sizeof(block));
        if (remaining > 0) {
            std::memcpy(block, current, remaining);
        }
        block[remaining] = 0x80;

        if (remaining >= 56) {
            processBlock(block);
            std::memset(block, 0, sizeof(block));
        }

        uint64_t bitLength = static_cast<uint64_t>(len) * 8ULL;
        block[56] = static_cast<uint8_t>(bitLength >> 56);
        block[57] = static_cast<uint8_t>(bitLength >> 48);
        block[58] = static_cast<uint8_t>(bitLength >> 40);
        block[59] = static_cast<uint8_t>(bitLength >> 32);
        block[60] = static_cast<uint8_t>(bitLength >> 24);
        block[61] = static_cast<uint8_t>(bitLength >> 16);
        block[62] = static_cast<uint8_t>(bitLength >> 8);
        block[63] = static_cast<uint8_t>(bitLength);
        processBlock(block);

        for (int i = 0; i < 8; ++i) {
            hash[i * 4] = static_cast<uint8_t>(state[i] >> 24);
            hash[i * 4 + 1] = static_cast<uint8_t>(state[i] >> 16);
            hash[i * 4 + 2] = static_cast<uint8_t>(state[i] >> 8);
            hash[i * 4 + 3] = static_cast<uint8_t>(state[i]);
        }
    }

    static void hmacSha256(const uint8_t* key, size_t keyLen,
                           const uint8_t* data, size_t dataLen,
                           uint8_t out[32]) {
        uint8_t k_ipad[64] = {0};
        uint8_t k_opad[64] = {0};
        uint8_t tk[32] = {0};

        if (keyLen > 64) {
            sha256(key, keyLen, tk);
            key = tk;
            keyLen = 32;
        }

        std::memcpy(k_ipad, key, keyLen);
        std::memcpy(k_opad, key, keyLen);
        for (int i = 0; i < 64; ++i) {
            k_ipad[i] ^= 0x36;
            k_opad[i] ^= 0x5c;
        }

        std::vector<uint8_t> inner(64 + dataLen);
        std::memcpy(inner.data(), k_ipad, 64);
        std::memcpy(inner.data() + 64, data, dataLen);
        uint8_t innerHash[32];
        sha256(inner.data(), inner.size(), innerHash);

        std::vector<uint8_t> outer(64 + 32);
        std::memcpy(outer.data(), k_opad, 64);
        std::memcpy(outer.data() + 64, innerHash, 32);
        sha256(outer.data(), outer.size(), out);

        secure_zero(tk, sizeof(tk));
    }

    static void pbkdf2HmacSha256(const uint8_t* password, size_t passwordLen,
                                 const uint8_t* salt, size_t saltLen,
                                 uint32_t iterations, uint8_t* output, size_t outputLen) {
        const size_t hashLen = 32;
        uint32_t blocks = static_cast<uint32_t>((outputLen + hashLen - 1) / hashLen);
        std::vector<uint8_t> block(saltLen + 4);
        std::vector<uint8_t> u(hashLen);
        std::vector<uint8_t> t(hashLen);

        for (uint32_t i = 1; i <= blocks; ++i) {
            std::memcpy(block.data(), salt, saltLen);
            block[saltLen + 0] = static_cast<uint8_t>(i >> 24);
            block[saltLen + 1] = static_cast<uint8_t>(i >> 16);
            block[saltLen + 2] = static_cast<uint8_t>(i >> 8);
            block[saltLen + 3] = static_cast<uint8_t>(i);

            hmacSha256(password, passwordLen, block.data(), block.size(), u.data());
            std::memcpy(t.data(), u.data(), hashLen);

            for (uint32_t j = 1; j < iterations; ++j) {
                hmacSha256(password, passwordLen, u.data(), hashLen, u.data());
                for (size_t k = 0; k < hashLen; ++k) {
                    t[k] ^= u[k];
                }
            }

            size_t offset = static_cast<size_t>(i - 1) * hashLen;
            size_t toCopy = std::min(outputLen - offset, hashLen);
            std::memcpy(output + offset, t.data(), toCopy);
        }
    }

    static bool aesCbcCrypt(const uint8_t* key, size_t keyLen,
                           const uint8_t* iv, uint8_t* buffer,
                           DWORD& bufferLen, DWORD maxLen, BOOL encrypt) {
        HCRYPTPROV hProv = 0;
        HCRYPTKEY hKey = 0;
        if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
            return false;
        }
        if (!aesKeyFromBytes(hProv, key, keyLen, hKey)) {
            CryptReleaseContext(hProv, 0);
            return false;
        }
        DWORD mode = CRYPT_MODE_CBC;
        if (!CryptSetKeyParam(hKey, KP_MODE, reinterpret_cast<BYTE*>(&mode), 0) ||
            !CryptSetKeyParam(hKey, KP_IV, const_cast<BYTE*>(iv), 0)) {
            CryptDestroyKey(hKey);
            CryptReleaseContext(hProv, 0);
            return false;
        }
        BOOL result = encrypt
            ? CryptEncrypt(hKey, 0, TRUE, 0, buffer, &bufferLen, maxLen)
            : CryptDecrypt(hKey, 0, TRUE, 0, buffer, &bufferLen);
        CryptDestroyKey(hKey);
        CryptReleaseContext(hProv, 0);
        return result != 0;
    }

    static bool aesCbcEncrypt(const uint8_t* key, size_t keyLen,
                              const uint8_t* iv, const uint8_t* plaintext,
                              size_t plaintextLen, std::vector<uint8_t>& ciphertext) {
        DWORD maxLen = static_cast<DWORD>(plaintextLen + 16);
        ciphertext.assign(maxLen, 0);
        std::memcpy(ciphertext.data(), plaintext, plaintextLen);
        DWORD len = static_cast<DWORD>(plaintextLen);
        if (!aesCbcCrypt(key, keyLen, iv, ciphertext.data(), len, maxLen, TRUE)) {
            return false;
        }
        ciphertext.resize(len);
        return true;
    }

    static bool aesCbcDecrypt(const uint8_t* key, size_t keyLen,
                              const uint8_t* iv, const uint8_t* ciphertext,
                              size_t ciphertextLen, std::vector<uint8_t>& plaintext) {
        if (ciphertextLen == 0 || ciphertextLen % 16 != 0) {
            return false;
        }
        plaintext.assign(ciphertextLen, 0);
        std::memcpy(plaintext.data(), ciphertext, ciphertextLen);
        DWORD len = static_cast<DWORD>(ciphertextLen);
        if (!aesCbcCrypt(key, keyLen, iv, plaintext.data(), len, static_cast<DWORD>(ciphertextLen), FALSE)) {
            return false;
        }
        plaintext.resize(len);
        return true;
    }

private:
    static bool aesKeyFromBytes(HCRYPTPROV hProv, const uint8_t* key, size_t keyLen, HCRYPTKEY& hKey) {
        if (keyLen != 16 && keyLen != 24 && keyLen != 32) {
            return false;
        }
        BLOBHEADER header;
        header.bType = PLAINTEXTKEYBLOB;
        header.bVersion = CUR_BLOB_VERSION;
        header.reserved = 0;
        header.aiKeyAlg = (keyLen == 16 ? CALG_AES_128 : keyLen == 24 ? CALG_AES_192 : CALG_AES_256);
        DWORD blobSize = sizeof(header) + sizeof(DWORD) + static_cast<DWORD>(keyLen);
        std::vector<uint8_t> blob(blobSize);
        std::memcpy(blob.data(), &header, sizeof(header));
        std::memcpy(blob.data() + sizeof(header), &keyLen, sizeof(DWORD));
        std::memcpy(blob.data() + sizeof(header) + sizeof(DWORD), key, keyLen);
        if (!CryptImportKey(hProv, blob.data(), blobSize, 0, 0, &hKey)) {
            return false;
        }
        return true;
    }
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

    static bool exists() {
        std::ifstream file(VAULT_FILE_NAME, std::ios::binary);
        return file.good();
    }

    static bool save(const Vault& vault, const std::string& password) {
        uint8_t salt[SALT_SIZE];
        uint8_t iv[IV_SIZE];
        uint8_t keyMaterial[KEY_SIZE * 2];
        uint8_t encKey[KEY_SIZE];
        uint8_t authKey[KEY_SIZE];
        uint8_t hmac[HMAC_SIZE];
        Header header{};
        std::vector<uint8_t> plaintext = vault.serialize();
        std::vector<uint8_t> ciphertext;

        if (!CryptoEngine::fillRandom(salt, SALT_SIZE) || !CryptoEngine::fillRandom(iv, IV_SIZE)) {
            return false;
        }
        CryptoEngine::pbkdf2HmacSha256(reinterpret_cast<const uint8_t*>(password.data()), password.size(), salt, SALT_SIZE,
                                       PBKDF2_ITERATIONS, keyMaterial, sizeof(keyMaterial));
        std::memcpy(encKey, keyMaterial, KEY_SIZE);
        std::memcpy(authKey, keyMaterial + KEY_SIZE, KEY_SIZE);

        if (!CryptoEngine::aesCbcEncrypt(encKey, KEY_SIZE, iv, plaintext.data(), plaintext.size(), ciphertext)) {
            return false;
        }
        CryptoEngine::hmacSha256(authKey, KEY_SIZE, ciphertext.data(), ciphertext.size(), hmac);

        std::memcpy(header.magic, VAULT_MAGIC, sizeof(header.magic));
        header.version = VAULT_VERSION;
        std::memcpy(header.salt, salt, SALT_SIZE);
        std::memcpy(header.iv, iv, IV_SIZE);
        header.ciphertextLen = static_cast<uint32_t>(ciphertext.size());

        std::ofstream file(VAULT_FILE_NAME, std::ios::binary);
        if (!file) {
            return false;
        }
        file.write(reinterpret_cast<const char*>(&header), sizeof(header));
        file.write(reinterpret_cast<const char*>(ciphertext.data()), ciphertext.size());
        file.write(reinterpret_cast<const char*>(hmac), HMAC_SIZE);
        return file.good();
    }

    static bool load(const std::string& password, Vault& vault) {
        Header header{};
        std::vector<uint8_t> ciphertext;
        std::vector<uint8_t> plaintext;
        uint8_t hmac[HMAC_SIZE];
        uint8_t computedHmac[HMAC_SIZE];
        uint8_t keyMaterial[KEY_SIZE * 2];
        uint8_t encKey[KEY_SIZE];
        uint8_t authKey[KEY_SIZE];

        std::ifstream file(VAULT_FILE_NAME, std::ios::binary);
        if (!file) {
            return false;
        }
        file.read(reinterpret_cast<char*>(&header), sizeof(header));
        if (!file || std::memcmp(header.magic, VAULT_MAGIC, sizeof(header.magic)) != 0 ||
            header.version != VAULT_VERSION || header.ciphertextLen == 0) {
            return false;
        }

        ciphertext.resize(header.ciphertextLen);
        file.read(reinterpret_cast<char*>(ciphertext.data()), ciphertext.size());
        file.read(reinterpret_cast<char*>(hmac), HMAC_SIZE);
        if (!file) {
            return false;
        }

        CryptoEngine::pbkdf2HmacSha256(reinterpret_cast<const uint8_t*>(password.data()), password.size(), header.salt, SALT_SIZE,
                                       PBKDF2_ITERATIONS, keyMaterial, sizeof(keyMaterial));
        std::memcpy(encKey, keyMaterial, KEY_SIZE);
        std::memcpy(authKey, keyMaterial + KEY_SIZE, KEY_SIZE);

        CryptoEngine::hmacSha256(authKey, KEY_SIZE, ciphertext.data(), ciphertext.size(), computedHmac);
        if (std::memcmp(hmac, computedHmac, HMAC_SIZE) != 0) {
            return false;
        }

        if (!CryptoEngine::aesCbcDecrypt(encKey, KEY_SIZE, header.iv, ciphertext.data(), ciphertext.size(), plaintext)) {
            return false;
        }

        if (!Vault::deserialize(plaintext, vault)) {
            return false;
        }
        return true;
    }
};

static bool readPassword(std::string& output, const char* prompt) {
    std::cout << prompt;
    output.clear();
#ifdef _WIN32
    int ch;
    while ((ch = _getch()) != EOF && ch != '\r' && ch != '\n') {
        if (ch == 8 || ch == 127) {
            if (!output.empty()) {
                output.pop_back();
                std::cout << "\b \b";
            }
        } else if (output.size() + 1 < MAX_FIELD_LENGTH) {
            output.push_back(static_cast<char>(ch));
            std::cout << '*';
        }
    }
#else
    std::getline(std::cin, output);
#endif
    std::cout << '\n';
    return true;
}

static bool readLine(std::string& output, const char* prompt) {
    std::cout << prompt;
    std::getline(std::cin, output);
    return true;
}

int main() {
    Vault vault;
    std::string masterPassword;
    std::string confirmPassword;

    if (VaultFile::exists()) {
        if (!readPassword(masterPassword, "Digite a Senha Mestra: ")) {
            return 1;
        }
        if (!VaultFile::load(masterPassword, vault)) {
            std::cout << "Senha incorreta ou arquivo de cofres inválido." << std::endl;
            return 1;
        }
        std::cout << "Cofre carregado com sucesso." << std::endl;
    } else {
        std::cout << "Nenhum cofre encontrado. Vamos criar um novo cofre." << std::endl;
        readPassword(masterPassword, "Defina uma nova Senha Mestra: ");
        readPassword(confirmPassword, "Confirme a Senha Mestra: ");
        if (masterPassword.empty() || masterPassword != confirmPassword) {
            std::cout << "Senhas não conferem ou são inválidas." << std::endl;
            return 1;
        }
        if (!VaultFile::save(vault, masterPassword)) {
            std::cout << "Falha ao criar o arquivo do cofre." << std::endl;
            return 1;
        }
        std::cout << "Cofre criado com sucesso." << std::endl;
    }

    while (true) {
        std::cout << "\nMenu:\n"
                  << "1. Listar entradas\n"
                  << "2. Adicionar entrada\n"
                  << "3. Remover entrada\n"
                  << "4. Salvar e sair\n"
                  << "Escolha: ";
        char option = 0;
        std::cin.get(option);
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');

        if (option == '1') {
            vault.print();
        } else if (option == '2') {
            VaultEntry entry;
            readLine(entry.site, "Site: ");
            readLine(entry.username, "Usuário: ");
            readLine(entry.password, "Senha: ");
            if (entry.site.empty() || entry.username.empty() || entry.password.empty()) {
                std::cout << "Todos os campos devem ser preenchidos." << std::endl;
                continue;
            }
            vault.addEntry(entry);
            std::cout << "Entrada adicionada." << std::endl;
        } else if (option == '3') {
            if (vault.entries.empty()) {
                std::cout << "Nenhuma entrada para remover." << std::endl;
                continue;
            }
            vault.print();
            std::string indexText;
            readLine(indexText, "Número da entrada a remover: ");
            size_t index = std::stoul(indexText);
            if (index == 0 || index > vault.entries.size()) {
                std::cout << "Índice inválido." << std::endl;
                continue;
            }
            vault.removeEntry(index - 1);
            std::cout << "Entrada removida." << std::endl;
        } else if (option == '4') {
            if (!VaultFile::save(vault, masterPassword)) {
                std::cout << "Falha ao salvar o arquivo do cofre." << std::endl;
                return 1;
            }
            std::cout << "Cofre salvo e encerrado." << std::endl;
            break;
        } else {
            std::cout << "Opção inválida." << std::endl;
        }
    }

    if (!masterPassword.empty()) {
        secure_zero(&masterPassword[0], masterPassword.size());
    }
    if (!confirmPassword.empty()) {
        secure_zero(&confirmPassword[0], confirmPassword.size());
    }
    return 0;
}
