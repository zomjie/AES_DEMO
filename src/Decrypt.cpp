#include <openssl/evp.h>
#include <openssl/aes.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <cstring>
#include <iomanip>

class FileDecryption {
private:
    EVP_CIPHER_CTX *ctx_cbc;    // 用于CBC模式的解密
    EVP_CIPHER_CTX *ctx_ctr;    // 用于CTR模式的加密

    void decrypt_block_ctr(const unsigned char* input, unsigned char* output, 
                          unsigned char* counter, size_t length) {
        unsigned char keystream[AES_BLOCK_SIZE];
        int outlen;
        EVP_EncryptUpdate(ctx_ctr, keystream, &outlen, counter, AES_BLOCK_SIZE);
        //print_hex("Counter", counter, AES_BLOCK_SIZE);
        //print_hex("Keystream", keystream, AES_BLOCK_SIZE);
        
        for (size_t i = 0; i < length; i++) {
            output[i] = input[i] ^ keystream[i];
        }
        
        for (int i = AES_BLOCK_SIZE - 1; i >= 0; i--) {
            if (++counter[i] != 0) break;
        }
    }

    void decrypt_single_block(const unsigned char* input, unsigned char* output) {
        int outlen;
        EVP_DecryptUpdate(ctx_cbc, output, &outlen, input, AES_BLOCK_SIZE);
    }

    void decrypt_block_cbc(const unsigned char* input, unsigned char* output, unsigned char* prev_cipher) {
        unsigned char temp[AES_BLOCK_SIZE];
        decrypt_single_block(input, temp);
        
        for (int i = 0; i < AES_BLOCK_SIZE; i++) {
            output[i] = temp[i] ^ prev_cipher[i];
        }
    }

    void print_hex(const char* name, const unsigned char* data, size_t len) {
        std::cout << name << ": ";
        for (size_t i = 0; i < len; i++) {
            std::cout << std::hex << std::setfill('0') << std::setw(2) 
                     << static_cast<int>(data[i]) << " ";
        }
        std::cout << std::dec << std::endl;  // 恢复十进制输出
    }

public:
    FileDecryption(const unsigned char* key, int key_bits = 128) {
        ctx_cbc = EVP_CIPHER_CTX_new();
        ctx_ctr = EVP_CIPHER_CTX_new();
        
        const EVP_CIPHER* cipher = EVP_aes_128_ecb();
        if (key_bits == 192) cipher = EVP_aes_192_ecb();
        else if (key_bits == 256) cipher = EVP_aes_256_ecb();
        
        // CBC模式使用解密初始化
        EVP_DecryptInit_ex(ctx_cbc, cipher, nullptr, key, nullptr);
        // CTR模式使用加密初始化
        EVP_EncryptInit_ex(ctx_ctr, cipher, nullptr, key, nullptr);
        
        EVP_CIPHER_CTX_set_padding(ctx_cbc, 0);
        EVP_CIPHER_CTX_set_padding(ctx_ctr, 0);
    }

    ~FileDecryption() {
        EVP_CIPHER_CTX_free(ctx_cbc);
        EVP_CIPHER_CTX_free(ctx_ctr);
    }

    bool decrypt_file_cbc(const std::string& input_file, const std::string& output_file) {
        std::ifstream in(input_file, std::ios::binary);
        std::ofstream out(output_file, std::ios::binary);
        
        if (!in || !out) return false;

        unsigned char iv[AES_BLOCK_SIZE];
        in.read(reinterpret_cast<char*>(iv), AES_BLOCK_SIZE);

        const size_t BUFFER_SIZE = 65536;
        std::vector<unsigned char> buffer(BUFFER_SIZE);
        std::vector<unsigned char> decrypted(BUFFER_SIZE);
        std::vector<unsigned char> prev_block(AES_BLOCK_SIZE);
        memcpy(prev_block.data(), iv, AES_BLOCK_SIZE);

        while (in) {
            in.read(reinterpret_cast<char*>(buffer.data()), BUFFER_SIZE);
            size_t bytes_read = in.gcount();
            
            if (bytes_read == 0) break;
            if (bytes_read % AES_BLOCK_SIZE != 0) return false;

            size_t blocks = bytes_read / AES_BLOCK_SIZE;
            
            for (size_t i = 0; i < blocks; i++) {
                decrypt_block_cbc(
                    buffer.data() + i * AES_BLOCK_SIZE,
                    decrypted.data() + i * AES_BLOCK_SIZE,
                    i == 0 ? prev_block.data() : buffer.data() + (i-1) * AES_BLOCK_SIZE
                );
            }

            if (in.eof()) {
                unsigned char* last_block = decrypted.data() + (blocks - 1) * AES_BLOCK_SIZE;
                size_t padding_size = last_block[AES_BLOCK_SIZE - 1];
                
                if (padding_size > 0 && padding_size <= AES_BLOCK_SIZE) {
                    bytes_read -= padding_size;
                }
            }

            out.write(reinterpret_cast<char*>(decrypted.data()), bytes_read);
        }

        return true;
    }

    bool decrypt_file_ctr(const std::string& input_file, const std::string& output_file) {
        std::ifstream in(input_file, std::ios::binary);
        std::ofstream out(output_file, std::ios::binary);
        
        if (!in || !out) return false;

        unsigned char counter[AES_BLOCK_SIZE];
        in.read(reinterpret_cast<char*>(counter), AES_BLOCK_SIZE);
        //print_hex("Counter", counter, AES_BLOCK_SIZE);  // 添加这行来打印counter值

        const size_t BUFFER_SIZE = 65536;
        std::vector<unsigned char> buffer(BUFFER_SIZE);
        std::vector<unsigned char> decrypted(BUFFER_SIZE);

        while (in) {
            in.read(reinterpret_cast<char*>(buffer.data()), BUFFER_SIZE);
            size_t bytes_read = in.gcount();
            
            if (bytes_read == 0) break;

            for (size_t i = 0; i < bytes_read; i += AES_BLOCK_SIZE) {
                size_t chunk_size = std::min(static_cast<size_t>(AES_BLOCK_SIZE), bytes_read - i);
                decrypt_block_ctr(
                    buffer.data() + i,
                    decrypted.data() + i,
                    counter,
                    chunk_size
                );
            }

            out.write(reinterpret_cast<char*>(decrypted.data()), bytes_read);
        }

        return true;
    }
};

int main() {
    unsigned char key[16] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                            0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10};
    
    FileDecryption decryptor(key);

    std::string input_cbc = "./ciphertext/doc_cbc.bin";
    std::string input_ctr = "./ciphertext/doc_ctr.bin";
    std::string output_cbc = "./decrypttext/decrypt_doc_cbc.doc";
    std::string output_ctr = "./decrypttext/decrypt_doc_ctr.doc";
    
    
    std::cout << "开始CBC模式解密..." << std::endl;
    if (decryptor.decrypt_file_cbc(input_cbc, output_cbc)) {
        std::cout << "CBC模式解密成功，输出文件: " << output_cbc << std::endl;
    } else {
        std::cout << "CBC模式解密失败" << std::endl;
    }
    
    std::cout << "开始CTR模式解密..." << std::endl;
    if (decryptor.decrypt_file_ctr(input_ctr, output_ctr)) {
        std::cout << "CTR模式解密成功，输出文件: " << output_ctr << std::endl;
    } else {
        std::cout << "CTR模式解密失败" << std::endl;
    }
    
    return 0;
}
