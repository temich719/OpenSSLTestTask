#include <iostream>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <string>
#include <utility>

using namespace std;

const int KEY_BITS = 2048;

string GetUserInput() {
    string user_input;
    cout << "Input some message: " << endl;
    getline(cin, user_input);
    return user_input;
}

EVP_PKEY* GenerateKeyPair() {
    EVP_PKEY* pkey = EVP_PKEY_new();
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    EVP_PKEY_keygen_init(ctx);
    EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, KEY_BITS);
    EVP_PKEY_keygen(ctx, &pkey);
    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

void PrintPubKey(EVP_PKEY* pkey) {
    BIO* pub_out = BIO_new(BIO_s_mem());
    PEM_write_bio_PUBKEY(pub_out, pkey);
    char* pub_key_str = nullptr;
    long pub_key_len = BIO_get_mem_data(pub_out, &pub_key_str);//????
    cout << "Public Key:" << endl;
    cout.write(pub_key_str, pub_key_len);
    BIO_free(pub_out);
}

void PrintPrivateKey(EVP_PKEY* pkey) {
    BIO* private_out = BIO_new(BIO_s_mem());
    PEM_write_bio_PrivateKey(private_out, pkey, NULL, NULL, 0, NULL, NULL);
    char* private_key_str = nullptr;
    long private_key_len = BIO_get_mem_data(private_out, &private_key_str);
    cout << "Private Key:" << endl;
    cout.write(private_key_str, private_key_len);
    BIO_free(private_out);
}

void PrintKeysToConsole(EVP_PKEY* pkey) {
    PrintPubKey(pkey);
    PrintPrivateKey(pkey);
}

void FreeResource(EVP_PKEY* pkey) {
    EVP_PKEY_free(pkey);
    EVP_cleanup();
}

void CheckCtxInit(EVP_PKEY_CTX* ctx, EVP_PKEY* pkey) {
    if (!ctx) {
        FreeResource(pkey);
        cout << "Error during context creation" << endl;
        return;
    }
}

void PrintEncrypted(unsigned char* encrypted_user_input, size_t encrypted_len) {
    cout << "Encrypted data: " << endl;
    for (size_t i = 0; i < encrypted_len; i++) {
        printf("%02X", encrypted_user_input[i]);
    }
    cout << endl;
}

void PrintDecrypted(unsigned char* decrypted_message, size_t decrypted_len) {
    cout << "Decryption result:" << endl;
    cout.write(reinterpret_cast<const char*>(decrypted_message), decrypted_len);
    cout << endl;
}

pair<unsigned char*, size_t> EncryptData(string user_input, EVP_PKEY* pkey, const unsigned char* user_input_data, int user_input_len) {
    unsigned char* encrypted_user_input = (unsigned char*)malloc(EVP_PKEY_size(pkey));
    size_t encrypted_len;
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, NULL);
    CheckCtxInit(ctx, pkey);
    if (EVP_PKEY_encrypt_init(ctx) <= 0 || 
        EVP_PKEY_encrypt(ctx, encrypted_user_input, &encrypted_len, user_input_data, user_input_len) <= 0) {
        cout << "Error during encryption" << endl;
        free(encrypted_user_input);
        EVP_PKEY_CTX_free(ctx);
        FreeResource(pkey);
        pair<unsigned char*, size_t> error;
        error.first = NULL;
        error.second = NULL;
        return error;
    }
    PrintEncrypted(encrypted_user_input, encrypted_len);
    EVP_PKEY_CTX_free(ctx);
    pair<unsigned char*, size_t> result;
    result.first = encrypted_user_input;
    result.second = encrypted_len;
    return result;
}

void DecryptData(EVP_PKEY* pkey, unsigned char* encrypted_user_input, size_t encrypted_len) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, NULL);
    CheckCtxInit(ctx, pkey);
    unsigned char* decrypted_message = (unsigned char*)malloc(EVP_PKEY_size(pkey));
    size_t decrypted_len;
    if (EVP_PKEY_decrypt_init(ctx) <= 0 || EVP_PKEY_decrypt(ctx, decrypted_message, &decrypted_len, encrypted_user_input, encrypted_len) <= 0) {
        cout << "Error during decryption" << endl;
        EVP_PKEY_CTX_free(ctx);
        free(decrypted_message);
        FreeResource(pkey);
        return;
    }
    PrintDecrypted(decrypted_message, decrypted_len);
    EVP_PKEY_CTX_free(ctx);
    free(decrypted_message);
}

void PrintHash(unsigned char* hash_value) {
    cout << "Hash value: " << endl;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        printf("%02x", hash_value[i]);
    }
    cout << endl;
}

void CalculateHashValue(const unsigned char* user_input_data, int user_input_len, unsigned char* hash_value) {
    SHA256(user_input_data, user_input_len, hash_value);
}

void PrintSignature(unsigned char* signature, unsigned int sign_len) {
    cout << "Signature:" << endl;
    for (size_t i = 0; i < sign_len; i++) {
        printf("%02X", signature[i]);
    }
    cout << endl;
}

unsigned int MakeSignature(EVP_PKEY* pkey, unsigned char* hash_value, unsigned char* signature) {
    unsigned int sign_len;
    EVP_MD_CTX* hash_ctx = EVP_MD_CTX_new();
    EVP_SignInit(hash_ctx, EVP_sha256());
    EVP_SignUpdate(hash_ctx, hash_value, SHA256_DIGEST_LENGTH);
    EVP_SignFinal(hash_ctx, signature, &sign_len, pkey);
    PrintSignature(signature, sign_len);
    EVP_MD_CTX_free(hash_ctx);
    return sign_len;
} 

void VerifySignature(EVP_PKEY* pkey, unsigned char* hash_value, unsigned char* signature, unsigned int sign_len) {
    EVP_MD_CTX* verify_ctx = EVP_MD_CTX_new();
    EVP_VerifyInit(verify_ctx, EVP_sha256());
    EVP_VerifyUpdate(verify_ctx, hash_value, SHA256_DIGEST_LENGTH);
    int verify_result = EVP_VerifyFinal(verify_ctx, signature, sign_len, pkey);
    EVP_MD_CTX_free(verify_ctx);

    if (verify_result == 1) {
        cout << "Signature is valid" << endl;
    }
    else if (verify_result == 0) {
        cout << "Signature is invalid" << endl;
    }
    else {
        cout << "Error during verification" << endl;
    }
}


int main() {
    OpenSSL_add_all_algorithms();

    string user_input = GetUserInput();
    const unsigned char* user_input_data = reinterpret_cast<const unsigned char*>(user_input.c_str());
    int user_input_len = user_input.length();

    EVP_PKEY* pkey = GenerateKeyPair();
    PrintKeysToConsole(pkey);

    pair<unsigned char*, size_t> encrypted = EncryptData(user_input, pkey, user_input_data, user_input_len);
    if (encrypted.first != NULL && encrypted.second != NULL) {
        unsigned char* encrypted_user_input = encrypted.first;
        DecryptData(pkey, encrypted_user_input, encrypted.second);
        free(encrypted_user_input);
    }
    unsigned char hash_value[SHA256_DIGEST_LENGTH];
    CalculateHashValue(user_input_data, user_input_len, hash_value);
    PrintHash(hash_value);

    unsigned char* signature = (unsigned char*)malloc(EVP_PKEY_size(pkey));
    unsigned int sign_len = MakeSignature(pkey, hash_value, signature);
    VerifySignature(pkey, hash_value, signature, sign_len);
    free(signature);
    FreeResource(pkey);

    return 0;
}
