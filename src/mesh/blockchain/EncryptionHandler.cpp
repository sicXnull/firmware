#include "EncryptionHandler.h"
#include "utils.h"
#include <memory>
#include <string>

uint8_t *EncryptionHandler::Binhash(const struct HashVector *test)
{
    size_t size = strlen(test->data);
    static uint8_t value[HASH_SIZE];

    BLAKE2b hash;
    hash.reset(32);
    hash.update(test->data, size);

    hash.finalize(value, sizeof(value));

    return value;
}

String EncryptionHandler::KDAhash(const struct HashVector *test)
{
    size_t size = strlen(test->data);
    uint8_t value[HASH_SIZE];

    BLAKE2b hash;
    hash.reset(32);
    hash.update(test->data, size);
    hash.finalize(value, sizeof(value));

    auto inputLength = sizeof(value);
    char output[base64::encodeLength(inputLength)];
    base64::encode(value, inputLength, output);
    String hashString = String(output);
    hashString.replace("+", "-");
    hashString.replace("/", "_");
    hashString.replace("=", "");
    return hashString;
}

void EncryptionHandler::HexToBytes(const std::string &hex, char *out)
{
    for (unsigned int i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        char byte = (char)strtol(byteString.c_str(), NULL, 16);
        out[i / 2] = byte;
    }
}

std::string EncryptionHandler::bytesToHex(const unsigned char *bytes, size_t length)
{
    std::string hexStr;
    hexStr.reserve(length * 2); // Reserve space to avoid multiple allocations
    for (size_t i = 0; i < length; ++i) {
        char hex[3];
        sprintf(hex, "%02x", bytes[i]);
        hexStr += hex;
    }
    return hexStr;
}

String EncryptionHandler::generateSignature(const std::string &public_key, const std::string &private_key, const uint8_t *hashBin)
{
    char publicKey[32];
    HexToBytes(public_key, publicKey);

    char privateKey[32];
    HexToBytes(private_key, privateKey);

    uint8_t signature[64];
    Ed25519::sign(signature, (uint8_t *)privateKey, (uint8_t *)publicKey, hashBin, HASH_SIZE);

    // Convert bytes to hex string
    String signHex = "";
    for (uint8_t i = 0; i < sizeof(signature); i++) {
        signHex += (signature[i] < 16 ? "0" : "") + String(signature[i], HEX);
    }
    return signHex;
}

void EncryptionHandler::add_pkcs7_padding(std::vector<unsigned char> &data, size_t block_size)
{
    size_t padding_size = block_size - (data.size() % block_size);
    data.insert(data.end(), padding_size, static_cast<unsigned char>(padding_size));
}

void EncryptionHandler::EvpKDF(const unsigned char *password, size_t password_len, const unsigned char *salt, size_t salt_len,
                               unsigned char *pOutKey, size_t key_size, unsigned char *pOutIV, size_t iv_size,
                               mbedtls_md_type_t md_type, int iterations)
{
    mbedtls_md_context_t md_ctx;
    mbedtls_md_init(&md_ctx);

    if (mbedtls_md_setup(&md_ctx, mbedtls_md_info_from_type(md_type), 1) != 0) {
        fprintf(stderr, "Failed to setup md context\n");
        return;
    }

    size_t block_size = mbedtls_md_get_size(mbedtls_md_info_from_type(md_type));
    std::vector<unsigned char> block(block_size);
    std::vector<unsigned char> derivedKey;

    size_t total_size = key_size + iv_size;

    while (derivedKey.size() < total_size) {
        mbedtls_md_starts(&md_ctx);
        if (!derivedKey.empty()) {
            mbedtls_md_update(&md_ctx, block.data(), block.size());
        }
        mbedtls_md_update(&md_ctx, password, password_len);
        mbedtls_md_update(&md_ctx, salt, salt_len); // Incorporate salt
        mbedtls_md_finish(&md_ctx, block.data());   // Finalize the block

        for (int i = 1; i < iterations; i++) {
            mbedtls_md_starts(&md_ctx);
            mbedtls_md_update(&md_ctx, block.data(), block_size);
            mbedtls_md_finish(&md_ctx, block.data()); // Correctly finalize the block once per iteration
        }

        derivedKey.insert(derivedKey.end(), block.begin(), block.end());
    }

    mbedtls_md_free(&md_ctx);

    // Ensure the derivedKey is long enough
    if (derivedKey.size() > total_size) {
        derivedKey.resize(total_size);
    }

    memcpy(pOutKey, derivedKey.data(), key_size);
    memcpy(pOutIV, derivedKey.data() + key_size, iv_size);
}

String EncryptionHandler::encrypt(const std::string &base64PublicKey, const std::string &payload)
{
    // Initialize mbedTLS structures
    mbedtls_aes_context aes;
    mbedtls_pk_context pk;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_rsa_context *rsa;

    // Initialize and seed the random number generator
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);
    mbedtls_aes_init(&aes);
    mbedtls_pk_init(&pk);

    // Seed the random number generator
    if (mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, nullptr, 0) != 0) {
        LOG_ERROR("Failed to initialize RNG\n");
        return "";
    }

    // Decode Base64 public key to binary
    size_t decodedKeyLength = base64::decodeLength(base64PublicKey.c_str());
    std::vector<uint8_t> binaryKey(decodedKeyLength);
    base64::decode(base64PublicKey.c_str(), binaryKey.data());
    std::string decodedKey(binaryKey.begin(), binaryKey.end());

    // Convert std::string to const unsigned char*
    const unsigned char *publicKey = reinterpret_cast<const unsigned char *>(decodedKey.c_str());
    size_t publicKeyLen = decodedKey.size() + 1;
    if (mbedtls_pk_parse_public_key(&pk, publicKey, publicKeyLen) != 0) {
        LOG_ERROR("Failed to parse public key\n");
        return "";
    }

    rsa = mbedtls_pk_rsa(pk);
    mbedtls_rsa_set_padding(rsa, MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_SHA256);

    // Generate a random 16-byte symmetric key
    unsigned char aesKey[16];
    mbedtls_ctr_drbg_random(&ctr_drbg, aesKey, sizeof(aesKey));

    // Convert symmetric key to hex-encoded string
    char symKeyHex[33];
    for (int i = 0; i < 16; i++) {
        sprintf(&symKeyHex[i * 2], "%02x", aesKey[i]);
    }
    symKeyHex[32] = '\0';

    // Encrypt the symmetric key using RSA-OAEP with SHA-256
    unsigned char buffer[512];
    size_t olen;
    if (mbedtls_rsa_rsaes_oaep_encrypt(rsa, mbedtls_ctr_drbg_random, &ctr_drbg, MBEDTLS_RSA_PUBLIC, nullptr, 0, sizeof(symKeyHex),
                                       reinterpret_cast<const unsigned char *>(symKeyHex), buffer) != 0) {
        LOG_ERROR("RSA encryption failed\n");
        return "";
    }
    olen = mbedtls_rsa_get_len(rsa);

    // Generate a random 8-byte salt
    unsigned char salt[8];
    mbedtls_ctr_drbg_random(&ctr_drbg, salt, sizeof(salt));
    unsigned char derivedKey[32], derivedIV[16];
    std::string symKeyString = std::string(symKeyHex);
    LOG_DEBUG("KEY: %s\n", symKeyString.c_str());

    // IMPORTANT: SymKeyHex must be 33 bytes (counting the null terminator), otherwise key derivation will differ from CryptoJS
    EvpKDF(reinterpret_cast<const unsigned char *>(symKeyHex), 33, salt, 8, derivedKey, 32, derivedIV, 16, MBEDTLS_MD_MD5, 1);

    std::string saltHex = bytesToHex(salt, 8);
    LOG_DEBUG("Salt: %s\n", saltHex.c_str());

    std::string ivHex = bytesToHex(derivedIV, 16);
    LOG_DEBUG("Derived IV: %s\n", ivHex.c_str());

    std::string keyHex = bytesToHex(derivedKey, 32);
    LOG_DEBUG("Derived KEY: %s\n", keyHex.c_str());

    // Set key length to 256 bits
    mbedtls_aes_setkey_enc(&aes, derivedKey, 256); // Using 256-bit encryption key

    // Add PKCS7 padding to the payload
    std::vector<unsigned char> paddedPayload(payload.begin(), payload.end());
    add_pkcs7_padding(paddedPayload, 16);

    // Encrypt the payload using AES-CBC
    std::vector<unsigned char> encryptedData(paddedPayload.size());
    unsigned char derivedIVCopy[16];
    memcpy(derivedIVCopy, derivedIV, sizeof(derivedIVCopy));
    mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT, paddedPayload.size(), derivedIVCopy, paddedPayload.data(),
                          encryptedData.data());

    std::string encryptedDataHex = bytesToHex(encryptedData.data(), encryptedData.size());
    LOG_DEBUG("Encrypted Data: %s\n", encryptedDataHex.c_str());

    // Combine prefix, salt and encryptedData
    std::vector<unsigned char> combinedData;
    const char *prefix = "Salted__";
    combinedData.insert(combinedData.end(), prefix, prefix + 8);
    combinedData.insert(combinedData.end(), salt, salt + sizeof(salt));
    combinedData.insert(combinedData.end(), encryptedData.begin(), encryptedData.end());

    // Base64 encode the encrypted AES key
    size_t encryptedKeyBase64Len = base64::encodeLength(olen);
    std::vector<char> encryptedKeyBase64(encryptedKeyBase64Len);
    base64::encode(buffer, olen, encryptedKeyBase64.data());

    // Base64 encode the combined data
    size_t combinedDataBase64Len = base64::encodeLength(combinedData.size());
    std::vector<char> combinedDataBase64(combinedDataBase64Len);
    base64::encode(combinedData.data(), combinedData.size(), combinedDataBase64.data());

    std::string encryptedCombinedDataStr(combinedDataBase64.begin(), combinedDataBase64.end());
    std::string encryptedKeyStr(encryptedKeyBase64.begin(), encryptedKeyBase64.end());

    // Concatenate the encoded strings with a delimiter
    String result = String(encryptedCombinedDataStr.c_str()) + ";;;;;" + String(encryptedKeyStr.c_str());
    LOG_DEBUG("+++++++++ RESULT OF ENCRYPT!!!:\n");
    logLongString(result);

    // Cleanup
    mbedtls_aes_free(&aes);
    mbedtls_pk_free(&pk);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);

    return result;
}