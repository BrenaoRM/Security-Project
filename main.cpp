// =============================================================================
// main.cpp
// -----------------------------------------------------------------------------
// Ponto de entrada do Cofre de Senhas. Contém apenas a interação com o
// usuário (menu de console); toda a lógica de criptografia e persistência
// está em vault.cpp / vault.hpp.
// =============================================================================
#include "vault.hpp"

#include <iostream>
#include <limits>
#include <string>

namespace {

void printMenu() {
    std::cout << "\nMenu:\n"
              << "1. Listar entradas\n"
              << "2. Adicionar entrada\n"
              << "3. Remover entrada\n"
              << "4. Salvar e sair\n"
              << "Escolha: ";
}

bool openOrCreateVault(Vault& vault, std::string& masterPassword) {
    if (VaultFile::exists()) {
        if (!readPassword(masterPassword, "Digite a Senha Mestra: ")) {
            return false;
        }
        if (!VaultFile::load(masterPassword, vault)) {
            std::cout << "Senha incorreta ou arquivo de cofre inválido." << std::endl;
            return false;
        }
        std::cout << "Cofre carregado com sucesso." << std::endl;
        return true;
    }

    std::cout << "Nenhum cofre encontrado. Vamos criar um novo cofre." << std::endl;
    std::string confirmPassword;
    readPassword(masterPassword, "Defina uma nova Senha Mestra: ");
    readPassword(confirmPassword, "Confirme a Senha Mestra: ");

    bool valid = !masterPassword.empty() && masterPassword == confirmPassword;
    if (!confirmPassword.empty()) {
        secure_zero(&confirmPassword[0], confirmPassword.size());
    }
    if (!valid) {
        std::cout << "Senhas não conferem ou são inválidas." << std::endl;
        return false;
    }
    if (!VaultFile::save(vault, masterPassword)) {
        std::cout << "Falha ao criar o arquivo do cofre." << std::endl;
        return false;
    }
    std::cout << "Cofre criado com sucesso." << std::endl;
    return true;
}

void handleAddEntry(Vault& vault) {
    VaultEntry entry;
    readLine(entry.site, "Site: ");
    readLine(entry.username, "Usuário: ");
    readLine(entry.password, "Senha: ");
    if (entry.site.empty() || entry.username.empty() || entry.password.empty()) {
        std::cout << "Todos os campos devem ser preenchidos." << std::endl;
        return;
    }
    vault.addEntry(entry);
    std::cout << "Entrada adicionada." << std::endl;
}

void handleRemoveEntry(Vault& vault) {
    if (vault.entries.empty()) {
        std::cout << "Nenhuma entrada para remover." << std::endl;
        return;
    }
    vault.print();
    std::string indexText;
    readLine(indexText, "Número da entrada a remover: ");
    try {
        size_t index = std::stoul(indexText);
        if (index == 0 || index > vault.entries.size()) {
            std::cout << "Índice inválido." << std::endl;
            return;
        }
        vault.removeEntry(index - 1);
        std::cout << "Entrada removida." << std::endl;
    } catch (const std::exception&) {
        std::cout << "Índice inválido." << std::endl;
    }
}

void runMenuLoop(Vault& vault, const std::string& masterPassword) {
    while (true) {
        printMenu();
        char option = 0;
        std::cin.get(option);
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');

        switch (option) {
            case '1':
                vault.print();
                break;
            case '2':
                handleAddEntry(vault);
                break;
            case '3':
                handleRemoveEntry(vault);
                break;
            case '4':
                if (!VaultFile::save(vault, masterPassword)) {
                    std::cout << "Falha ao salvar o arquivo do cofre." << std::endl;
                    return;
                }
                std::cout << "Cofre salvo e encerrado." << std::endl;
                return;
            default:
                std::cout << "Opção inválida." << std::endl;
                break;
        }
    }
}

} // namespace

int main() {
    Vault vault;
    std::string masterPassword;

    if (!openOrCreateVault(vault, masterPassword)) {
        return 1;
    }

    runMenuLoop(vault, masterPassword);

    // Segurança de memória: apaga a senha mestra antes de encerrar.
    if (!masterPassword.empty()) {
        secure_zero(&masterPassword[0], masterPassword.size());
    }
    return 0;
}
