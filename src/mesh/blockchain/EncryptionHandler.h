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

/**
 * @struct HashVector
 * @brief A structure to hold data and its corresponding hash.
 *
 * This structure is used to store a name, data, and the resulting hash of the data.
 * The hash is generated using a specific hashing algorithm and is stored as a byte array.
 */
struct HashVector {
    const char *name;        ///< The name associated with the data.
    const char *data;        ///< The data to be hashed.
    uint8_t hash[HASH_SIZE]; ///< The resulting hash of the data.
};

class EncryptionHandler
{
  public:
    EncryptionHandler() = default;
    ~EncryptionHandler() = default;

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
     * Converts a byte array to a hexadecimal string.
     *
     * This method takes a pointer to a byte array and its length, and converts the bytes
     * into a hexadecimal string representation.
     *
     * @param bytes A pointer to the byte array to be converted.
     * @param length The length of the byte array.
     * @return A string containing the hexadecimal representation of the byte array.
     */
    std::string bytesToHex(const unsigned char *bytes, size_t length);

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
    /**
     * Adds PKCS7 padding to the given data.
     *
     * @param data The data to which padding will be added.
     * @param block_size The block size to use for padding.
     */
    void add_pkcs7_padding(std::vector<unsigned char> &data, size_t block_size);

    /**
     * Derives a key and IV using the EVP Key Derivation Function (KDF).
     *
     * Implemented C++ version of the EvpKDF key derivation algorithm used by CryptoJS:
     * https://github.com/CryptoStore/crypto-js/blob/3.1.2/src/cipher-core.js#L753
     * https://github.com/CryptoStore/crypto-js/blob/3.1.2/src/evpkdf.js#L55
     * 
     * @param password The password used for key derivation.
     * @param password_len The length of the password.
     * @param salt The salt used for key derivation.
     * @param salt_len The length of the salt.
     * @param pOutKey The output buffer for the derived key.
     * @param key_size The size of the derived key.
     * @param pOutIV The output buffer for the derived IV.
     * @param iv_size The size of the derived IV.
     * @param md_type The message digest type to use.
     * @param iterations The number of iterations to use for key derivation.
     */
    void EvpKDF(const unsigned char *password, size_t password_len, const unsigned char *salt, size_t salt_len,
                unsigned char *pOutKey, size_t key_size, unsigned char *pOutIV, size_t iv_size, mbedtls_md_type_t md_type,
                int iterations);
};