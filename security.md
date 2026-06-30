Com base nos conceitos de segurança abordados nos documentos fornecidos, apresento dois projetos de programação distintos: um focado em **segurança de dados em repouso** (Cofre de Senhas) e outro em **segurança de sistemas distribuídos** (Transferência Segura de Arquivos).

---

### Projeto 1: Cofre de Senhas Local com Criptografia em Repouso

Este projeto foca no conceito de **dados em repouso (at-rest data encryption)** e no armazenamento seguro de segredos usando hashing e salting.

#### 1. Detalhamento e Conceitos Utilizados
*   **Autenticação por "O que você sabe":** Uso de uma senha mestra para derivar a chave de acesso.
*   **Hashing e Salting:** A senha mestra não é armazenada; apenas seu hash criptográfico com um *salt* aleatório para evitar ataques de dicionário.
*   **Criptografia Simétrica (AES):** Os dados são criptografados com uma chave simétrica de 128 ou 256 bits antes de serem salvos no disco.
*   **Princípio do Menor Privilégio:** A chave e os dados decifrados permanecem na RAM apenas o tempo necessário e são descartados após o uso.

#### 2. Arquitetura e Diagrama
A arquitetura baseia-se em uma aplicação que interage com um arquivo binário criptografado.

**Diagrama de Fluxo:**
```text
[Usuário] -> (Senha Mestra) -> [App] -> (Derivação de Chave via Hash/Salt)
                                 |
 [Arquivo Criptografado] <--- [AES Encrypt/Decrypt] ---> [Buffer em RAM (Dados Planos)]
```

#### 3. Código Inicial em C (Esqueleto)
```c
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
// Nota: Em um projeto real, utilizaria bibliotecas como OpenSSL ou Libsodium.

typedef struct {
    char site;
    char username;
    char password;
} Entry;

// Função para simular o hashing com salt para a senha mestra
void hash_master_password(const char* pass, char* salt, char* output_hash) {
    // Implementação de SHA-3 ou similar conforme recomendado
}

// Função para criptografia AES simétrica
void aes_encrypt_file(Entry* data, int count, const char* key) {
    // Criptografa o buffer antes de salvar no disco
}

int main() {
    char master_pass;
    printf("Digite a Senha Mestra: ");
    scanf("%s", master_pass);
    
    // 1. Verificar Hash/Salt da senha mestra
    // 2. Se correto, carregar arquivo e decifrar em RAM
    // 3. Mostrar menu de senhas
    // 4. Limpar RAM antes de sair
    
    return 0;
}
```

#### 4. Roteiro de Implementação
1.  **Configuração do Ambiente:** Integrar uma biblioteca de criptografia (ex: OpenSSL).
2.  **Módulo de Autenticação:** Implementar a lógica de *salt* aleatório e hashing de senha (ex: SHA-256 ou SHA-3).
3.  **Gerenciamento de Arquivo:** Criar a estrutura de dados para as entradas e funções de I/O binário.
4.  **Integração Criptográfica:** Implementar o modo de criptografia AES para o arquivo.
5.  **Segurança de Memória:** Garantir que a chave decifrada e os dados planos sejam apagados da RAM (sobrescritos com zeros) ao fechar o programa.

---