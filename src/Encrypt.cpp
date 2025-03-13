#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <cstring>
#include <iomanip>

class FileEncryption {
private:
    EVP_CIPHER_CTX *ctx;
    unsigned char iv[AES_BLOCK_SIZE];
    unsigned char counter[AES_BLOCK_SIZE];

    void encrypt_single_block(const unsigned char* input, unsigned char* output) {
        int outlen;
        EVP_EncryptUpdate(ctx, output, &outlen, input, AES_BLOCK_SIZE);
    }

    void encrypt_block_cbc(const unsigned char* input, unsigned char* output) {
        unsigned char temp[AES_BLOCK_SIZE];
        for (int i = 0; i < AES_BLOCK_SIZE; i++) {
            temp[i] = input[i] ^ iv[i];
        }
        encrypt_single_block(temp, output);
        memcpy(iv, output, AES_BLOCK_SIZE);
    }

    void encrypt_block_ctr(const unsigned char* input, unsigned char* output, size_t length) {
        unsigned char keystream[AES_BLOCK_SIZE];
        encrypt_single_block(counter, keystream);

	//print_hex("keystream", keystream, AES_BLOCK_SIZE);
        
        for (size_t i = 0; i < length; i++) {
            output[i] = input[i] ^ keystream[i];
        }
        
        for (int i = AES_BLOCK_SIZE - 1; i >= 0; i--) {
            if (++counter[i] != 0) break;
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
    FileEncryption(const unsigned char* key, int key_bits = 128) {
        ctx = EVP_CIPHER_CTX_new();
        RAND_bytes(iv, AES_BLOCK_SIZE);
        memcpy(counter, iv, AES_BLOCK_SIZE);
        
        const EVP_CIPHER* cipher = EVP_aes_128_ecb();
        if (key_bits == 192) cipher = EVP_aes_192_ecb();
        else if (key_bits == 256) cipher = EVP_aes_256_ecb();
        
        EVP_EncryptInit_ex(ctx, cipher, nullptr, key, nullptr);
        EVP_CIPHER_CTX_set_padding(ctx, 0);
    }

    ~FileEncryption() {
        EVP_CIPHER_CTX_free(ctx);
    }

    bool encrypt_file_cbc(const std::string& input_file, const std::string& output_file) {
        std::ifstream in(input_file, std::ios::binary);
        std::ofstream out(output_file, std::ios::binary);
        
        if (!in || !out) {
		std::cout<<"File path error"<<std::endl;
		return false;
    	}

        out.write(reinterpret_cast<char*>(iv), AES_BLOCK_SIZE);

        const size_t BUFFER_SIZE = 65536;
        std::vector<unsigned char> buffer(BUFFER_SIZE);
        std::vector<unsigned char> encrypted(BUFFER_SIZE);

        while (in) {
            in.read(reinterpret_cast<char*>(buffer.data()), BUFFER_SIZE);
            size_t bytes_read = in.gcount();
            
            if (bytes_read == 0) break;

            size_t full_blocks = bytes_read / AES_BLOCK_SIZE;
            
            for (size_t i = 0; i < full_blocks; i++) {
                encrypt_block_cbc(
                    buffer.data() + i * AES_BLOCK_SIZE,
                    encrypted.data() + i * AES_BLOCK_SIZE
                );
            }

            if (full_blocks > 0) {
                out.write(
                    reinterpret_cast<char*>(encrypted.data()),
                    full_blocks * AES_BLOCK_SIZE
                );
            }

            size_t remaining = bytes_read % AES_BLOCK_SIZE;
            
            if (in.eof()) {
                unsigned char last_block[AES_BLOCK_SIZE];
                unsigned char encrypted_last[AES_BLOCK_SIZE];
                
                if (remaining > 0) {
                    memcpy(last_block, buffer.data() + full_blocks * AES_BLOCK_SIZE, remaining);
                    size_t padding_size = AES_BLOCK_SIZE - remaining;
                    for (size_t i = remaining; i < AES_BLOCK_SIZE; i++) {
                        last_block[i] = padding_size;
                    }
                } else {
                    memset(last_block, AES_BLOCK_SIZE, AES_BLOCK_SIZE);
                }
                
                encrypt_block_cbc(last_block, encrypted_last);
                out.write(reinterpret_cast<char*>(encrypted_last), AES_BLOCK_SIZE);
                break;
            }
        }

        return true;
    }

    bool encrypt_file_ctr(const std::string& input_file, const std::string& output_file) {
        std::ifstream in(input_file, std::ios::binary);
        std::ofstream out(output_file, std::ios::binary);
        
        if (!in || !out) return false;

        out.write(reinterpret_cast<char*>(counter), AES_BLOCK_SIZE);
	//print_hex("counter", counter, AES_BLOCK_SIZE);

        const size_t BUFFER_SIZE = 65536;
        std::vector<unsigned char> buffer(BUFFER_SIZE);
        std::vector<unsigned char> encrypted(BUFFER_SIZE);

        while (in) {
            in.read(reinterpret_cast<char*>(buffer.data()), BUFFER_SIZE);
            size_t bytes_read = in.gcount();
            
            if (bytes_read == 0) break;

            for (size_t i = 0; i < bytes_read; i += AES_BLOCK_SIZE) {
                size_t chunk_size = std::min(static_cast<size_t>(AES_BLOCK_SIZE), bytes_read - i);
                encrypt_block_ctr(
                    buffer.data() + i,
                    encrypted.data() + i,
                    chunk_size
                );
            }

            out.write(reinterpret_cast<char*>(encrypted.data()), bytes_read);
        }

        return true;
    }
};

int main() {
    unsigned char key[16] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                            0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10};
    
    FileEncryption encryptor(key);
    
    std::string input_file = "./plaintext/test.doc";
    std::string output_cbc = "./ciphertext/doc_cbc.bin";
    std::string output_ctr = "./ciphertext/doc_ctr.bin";
    
    std::cout << "开始CBC模式加密..." << std::endl;
    if (encryptor.encrypt_file_cbc(input_file, output_cbc)) {
        std::cout << "CBC模式加密成功，输出文件: " << output_cbc << std::endl;
    } else {
        std::cout << "CBC模式加密失败" << std::endl;
    }
    
    std::cout << "开始CTR模式加密..." << std::endl;
    if (encryptor.encrypt_file_ctr(input_file, output_ctr)) {
        std::cout << "CTR模式加密成功，输出文件: " << output_ctr << std::endl;
    } else {
        std::cout << "CTR模式加密失败" << std::endl;
    }
    
    return 0;
}
