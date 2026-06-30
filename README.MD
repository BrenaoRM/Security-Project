# Cofre de Senhas (Password Vault) — vsfs-style local secrets manager

Este projeto implementa um **cofre de senhas local** em C++, com criptografia
de dados em repouso. Ele cria um arquivo binário (`vault.dat`) que armazena,
de forma cifrada e autenticada, uma lista de credenciais (site / usuário /
senha), protegidas por uma única senha mestra.

---

## Arquitetura do Arquivo do Cofre

O `vault.dat` é estruturado em três regiões sequenciais, no formato **PWV1**:

```text
[ HEADER | CIPHERTEXT (AES-256-CBC) | HMAC-SHA256 ]
```

* **`HEADER`:** magic (`"PWV1"`), versão, salt (16 bytes), IV (16 bytes) e o
  tamanho do ciphertext.
* **`CIPHERTEXT`:** todas as entradas do cofre (site/usuário/senha),
  serializadas e cifradas com AES-256-CBC.
* **`HMAC-SHA256`:** autentica o ciphertext (esquema *Encrypt-then-MAC*),
  verificado **antes** de qualquer tentativa de decifragem.

A chave mestra nunca é armazenada. A cada `save`/`load`, ela é usada apenas
para derivar, via **PBKDF2-HMAC-SHA256** (100.000 iterações) sobre o `salt`
do header, 64 bytes de material de chave: os primeiros 32 viram a chave de
**cifragem** (AES) e os 32 seguintes a chave de **autenticação** (HMAC).

### Estruturas Usadas (C++)

```cpp
struct Header {
    char     magic[4];          // "PWV1"
    uint8_t  version;
    uint8_t  salt[SALT_SIZE];   // 16 bytes
    uint8_t  iv[IV_SIZE];       // 16 bytes
    uint32_t ciphertextLen;
};

class VaultEntry {
public:
    std::string site;
    std::string username;
    std::string password;
};
```

---

## Arquivos do Projeto

O código está estruturado nos seguintes arquivos:
1. **`vault.hpp`**: cabeçalho com a definição das classes `VaultEntry`,
   `Vault`, `CryptoEngine` e `VaultFile`.
2. **`vault.cpp`**: implementação da serialização das entradas, das
   primitivas criptográficas (SHA-256, HMAC-SHA256, PBKDF2, AES-256-CBC) e da
   persistência do cofre em disco.
3. **`main.cpp`**: interface de console (menu interativo) que usa as classes
   acima para criar/abrir o cofre e gerenciar as entradas.

---

## Como Compilar e Executar

> O projeto usa a **Windows CryptoAPI** (`wincrypt.h`) para aleatoriedade e
> AES, então só compila e roda no **Windows**.

### Compilação

```bash
g++ -std=c++17 -Wall -Wextra -O2 vault.cpp main.cpp -o vault.exe -ladvapi32
```

Ou, com Visual Studio (Developer Command Prompt):

```bash
cl /std:c++17 /O2 vault.cpp main.cpp /link advapi32.lib
```

### Execução

```bash
.\vault.exe
```

* Se não existir um `vault.dat` na pasta, o programa pede para você definir
  uma nova Senha Mestra e cria o cofre.
* Se já existir um `vault.dat`, o programa pede a Senha Mestra para
  decifrá-lo e carregar as entradas.

---

## Comandos Disponíveis (menu interativo)

O cofre não usa argumentos de linha de comando — toda a interação acontece
pelo menu numérico exibido após abrir/criar o cofre:

* `1` — **Listar entradas**: mostra site, usuário e senha de cada entrada
  registrada.
* `2` — **Adicionar entrada**: pede site, usuário e senha e adiciona ao
  cofre em memória (ainda não grava em disco).
* `3` — **Remover entrada**: lista as entradas e remove a de índice
  informado.
* `4` — **Salvar e sair**: serializa, cifra e grava o cofre em `vault.dat`,
  encerrando o programa.

Nenhuma alteração é persistida em disco até a opção `4` ser escolhida.

---

## Segurança de Memória

Ao final da execução (ou logo após o uso), os seguintes dados são apagados
da RAM com `secure_zero` (sobrescrita byte a byte, sem otimização do
compilador):

* a Senha Mestra digitada (`main.cpp`);
* a chave derivada (`keyMaterial`) e as chaves de cifragem/autenticação
  (`encKey`, `authKey`) usadas em cada `save`/`load` (`vault.cpp`);
* o buffer de texto plano decifrado durante o `load` (`vault.cpp`).

## API

Você também pode usar as classes `VaultFile`/`Vault` diretamente em outro
código C++:

```cpp
#include "vault.hpp"

Vault vault;

// Criar/abrir o cofre
VaultFile::save(vault, "minha-senha-mestra");      // cria vault.dat
VaultFile::load("minha-senha-mestra", vault);       // carrega vault.dat

// Operações sobre as entradas
VaultEntry entry{"github.com", "meu_usuario", "minha_senha_forte"};
vault.addEntry(entry);
vault.removeEntry(0);
vault.print();
```
