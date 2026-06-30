// =============================================================================
// vault.hpp
// -----------------------------------------------------------------------------
// Declarações públicas do Cofre de Senhas (Password Vault).
//
// Este cabeçalho define a interface de todas as classes do projeto:
//   - VaultEntry    : uma entrada individual (site / usuário / senha)
//   - Vault         : a coleção de entradas em memória
//   - CryptoEngine  : primitivas criptográficas (SHA-256, HMAC, PBKDF2, AES-CBC)
//   - VaultFile     : leitura/escrita do cofre criptografado em disco
//
// A implementação de cada função fica em vault.cpp; main.cpp é o único
// arquivo que contém a função main() e a interação com o usuário.
// =============================================================================
#ifndef VAULT_HPP
#define VAULT_HPP

#include <cstdint>
#include <string>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#include <wincrypt.h>
#endif

// --------------------------------------------------------------------------
// Constantes globais do formato do cofre
// --------------------------------------------------------------------------
static constexpr const char VAULT_FILE_NAME[] = "vault.dat";
static constexpr const char VAULT_MAGIC[]      = "PWV1";
static constexpr uint8_t   VAULT_VERSION       = 1;
static constexpr size_t    SALT_SIZE           = 16;
static constexpr size_t    IV_SIZE             = 16;
static constexpr size_t    KEY_SIZE            = 32;
static constexpr size_t    HMAC_SIZE           = 32;
static constexpr uint32_t  PBKDF2_ITERATIONS   = 100000;
static constexpr size_t    MAX_FIELD_LENGTH    = 256;

// Apaga "len" bytes de memória de forma que o compilador não otimize a
// limpeza (usado para zerar senhas/chaves antes de sair de escopo).
void secure_zero(void* ptr, size_t len);

// =============================================================================
// VaultEntry — uma credencial (site, usuário, senha)
// =============================================================================
class VaultEntry {
public:
    std::string site;
    std::string username;
    std::string password;

    // Serializa a entrada (formato: uint16 length + bytes, por campo).
    void serialize(std::vector<uint8_t>& output) const;

    // Lê uma entrada a partir de um buffer binário, avançando "data"/"left".
    static bool deserialize(const uint8_t*& data, size_t& left, VaultEntry& entry);

private:
    static void appendUint16(std::vector<uint8_t>& output, uint16_t value);
    static void appendString(std::vector<uint8_t>& output, const std::string& value);
    static bool readString(const uint8_t*& data, size_t& left, std::string& output);
};

// =============================================================================
// Vault — coleção de entradas mantida em memória (dados em claro)
// =============================================================================
class Vault {
public:
    std::vector<VaultEntry> entries;

    void print() const;
    void addEntry(const VaultEntry& entry);
    bool removeEntry(size_t index);

    // Serializa todas as entradas (uint32 count + entradas) em um buffer
    // que depois é criptografado por VaultFile::save.
    std::vector<uint8_t> serialize() const;

    // Reconstrói o vault a partir do buffer decifrado por VaultFile::load.
    static bool deserialize(const std::vector<uint8_t>& data, Vault& vault);
};

// =============================================================================
// CryptoEngine — primitivas criptográficas usadas pelo cofre
// =============================================================================
class CryptoEngine {
public:
    // Gera bytes aleatórios criptograficamente seguros (CryptGenRandom no
    // Windows, /dev/urandom em outras plataformas).
    static bool fillRandom(uint8_t* buffer, size_t size);

    // SHA-256 (implementação própria, sem dependências externas).
    static void sha256(const uint8_t* data, size_t len, uint8_t hash[32]);

    // HMAC-SHA256.
    static void hmacSha256(const uint8_t* key, size_t keyLen,
                            const uint8_t* data, size_t dataLen,
                            uint8_t out[32]);

    // PBKDF2-HMAC-SHA256: deriva "outputLen" bytes de material de chave a
    // partir da senha mestra + salt.
    static void pbkdf2HmacSha256(const uint8_t* password, size_t passwordLen,
                                  const uint8_t* salt, size_t saltLen,
                                  uint32_t iterations, uint8_t* output, size_t outputLen);

    // AES-256-CBC via Windows CryptoAPI (CSP "AES Cryptographic Provider").
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

// =============================================================================
// VaultFile — persistência do cofre em disco (formato PWV1)
// =============================================================================
//
// Layout do arquivo:
//   [Header][ciphertext (AES-256-CBC)][HMAC-SHA256 do ciphertext]
//
// A chave mestra deriva, via PBKDF2, 64 bytes: os primeiros 32 são a chave
// de cifragem (AES) e os 32 seguintes são a chave de autenticação (HMAC),
// seguindo o padrão Encrypt-then-MAC.
// =============================================================================
class VaultFile {
public:
    struct Header {
        char     magic[4];
        uint8_t  version;
        uint8_t  salt[SALT_SIZE];
        uint8_t  iv[IV_SIZE];
        uint32_t ciphertextLen;
    };

    static bool exists();
    static bool save(const Vault& vault, const std::string& password);
    static bool load(const std::string& password, Vault& vault);
};

// --------------------------------------------------------------------------
// Entrada de dados do usuário (console)
// --------------------------------------------------------------------------
bool readPassword(std::string& output, const char* prompt); // entrada oculta (echo '*')
bool readLine(std::string& output, const char* prompt);     // entrada normal

#endif // VAULT_HPP
