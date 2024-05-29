#pragma once
#include "BLAKE2b.h"
#include "configuration.h"
#include "mbedtls/aes.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/pk.h"
#include "mbedtls/pkcs5.h"

#include "Ed25519.h"
#include "arduino_base64.hpp"

#include <string>
#include <vector>

#define HASH_SIZE 32

struct HashVector {
    const char *name;
    const char *data;
    uint8_t hash[HASH_SIZE];
};

class EncryptionHandler {
public:
    EncryptionHandler();
    ~EncryptionHandler();

    /**
     * Generates a binary hash from the given HashVector.
     *
     * @param test A pointer to the HashVector containing the data to hash.
     * @return A pointer to the resulting binary hash.
     */
    uint8_t *Binhash(const struct HashVector *test);

    /**
     * Generates a Kadena hash from the given HashVector.
     *
     * @param test A pointer to the HashVector containing the data to hash.
     * @return A String containing the Kadena hash.

     */
    String KDAhash(const struct HashVector *test);

    /**

     * Converts a hexadecimal string to a byte array.
     *
     * @param out A pointer to the output byte array.
     */
    void HexToBytes(const std::string &hex, char *out);

    /**
     * Generates a digital signature for a given binary hash.
     *
     * This method takes a binary hash as input and generates a digital signature using the provided public and private keys.
     * The signature is used to authenticate transactions or data when interacting with the blockchain.
     *
     * @param public_key The public key used for the digital signature.
     * @param private_key The private key used for the digital signature.
     * @param hashBin A pointer to the binary hash that needs to be signed.
     * @return A String containing the hexadecimal representation of the digital signature.
     */
    String generateSignature(const std::string &public_key, const std::string &private_key, const uint8_t *hashBin);
    /**
     * Encrypts a payload using a given public key.
     *
     * This method encrypts the provided payload using the specified public key.
     * The encryption process involves generating a symmetric key, encrypting the payload with AES,
     * and then encrypting the symmetric key with RSA.
     *
     * @param publicKey The public key used for encryption, encoded in Base64.
     * @param payload The data to be encrypted.
     * @return A string containing the encrypted payload.
     */
    String encrypt(const std::string &publicKey, const std::string &payload);

private:
    void add_pkcs7_padding(std::vector<unsigned char>& data, size_t block_size);
    void EvpKDF(const unsigned char *password, size_t password_len,
                const unsigned char *salt, size_t salt_len,
                unsigned char *pOutKey, size_t key_size,
                unsigned char *pOutIV, size_t iv_size,
                mbedtls_md_type_t md_type, int iterations);
    void logEncryptionInfo(const unsigned char* key, size_t keySize, const unsigned char* iv, size_t ivSize, const unsigned char* salt, size_t saltSize, const std::vector<unsigned char>& encryptedData);
};

