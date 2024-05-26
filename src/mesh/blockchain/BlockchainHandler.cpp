#if !MESHTASTIC_EXCLUDE_WEBSERVER
#include "BlockchainHandler.h"
#include "FSCommon.h"
#include "HTTPClient.h"
#include "WiFi.h"
#include "mbedtls/aes.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/pk.h"
#include "mbedtls/pkcs5.h"
#include "memGet.h"
#include "mesh/wifi/WiFiAPClient.h"
#include <cstdio>
#include <ctime>
#include <fstream>
#include <iomanip>
#include <memory>
#include <sstream>

// Redefine strptime in your source to avoid IRAM issue
char *strptime(const char *str, const char *format, struct tm *tm)
{
    if (sscanf(str, format, &tm->tm_year, &tm->tm_mon, &tm->tm_mday, &tm->tm_hour, &tm->tm_min, &tm->tm_sec) == 6) {
        tm->tm_year -= 1900; // Adjust year to be relative to 1900
        tm->tm_mon -= 1;     // Adjust month to be 0-based
        return (char *)(str + strlen(str));
    }
    return NULL;
}

String getCurrentTimestamp()
{
    // Get current time
    std::time_t now = std::time(nullptr);
    std::tm *now_tm = std::gmtime(&now);

    // Use stringstream to format the time
    std::ostringstream oss;
    oss << std::put_time(now_tm, "%Y-%m-%d %H:%M:%S");
    oss << " UTC";

    return String(oss.str().c_str());
}

void logLongString(const String &str, size_t chunkSize = 50)
{
    size_t len = str.length();
    if (len <= chunkSize) {
        LOG_INFO("%s\n", str.c_str());
    } else {
        size_t i = 0;
        while (i < len) {
            size_t end = std::min(i + chunkSize, len);
            LOG_INFO("%s\n", str.substring(i, end).c_str());
            i = end;
        }
    }
}

// Function to convert enum to string
std::string blockchainStatusToString(BlockchainStatus status)
{
    switch (status) {
    case BlockchainStatus::OK:
        return "OK";
    case BlockchainStatus::NO_WIFI:
        return "NO_WIFI";
    case BlockchainStatus::HTTP_ERROR:
        return "HTTP_ERROR";
    case BlockchainStatus::EMPTY_RESPONSE:
        return "EMPTY_RESPONSE";
    case BlockchainStatus::PARSING_ERROR:
        return "PARSING_ERROR";
    case BlockchainStatus::NODE_NOT_FOUND:
        return "NODE_NOT_FOUND";
    case BlockchainStatus::READY:
        return "READY";
    case BlockchainStatus::NOT_DUE:
        return "NOT_DUE";
    default:
        return "UNKNOWN_STATUS";
    }
}

BlockchainHandler::BlockchainHandler(const std::string public_key, const std::string private_key)
    : public_key_(public_key), private_key_(private_key)
{
    kda_server_ = "http://kda.crankk.org/chainweb/0.0/mainnet01/chain/19/pact/api/v1/";
}

bool BlockchainHandler::isWalletConfigValid()
{
    return moduleConfig.wallet.enabled && public_key_.length() == 64 && private_key_.length() == 64;
}

int32_t BlockchainHandler::performNodeSync(HttpAPI *webAPI)
{

    LOG_INFO("\nWallet public key: %s\n", public_key_.data());
    LOG_INFO("\nWallet private key: %s\n", private_key_.data());

    if (!isWalletConfigValid() || !isWifiAvailable()) {
        return 300000; // Every 5 minutes.
    }
    char nodeIdHex[9];
    sprintf(nodeIdHex, "%08x", nodeDB->getNodeNum());
    String nodeId = String(nodeIdHex);
    LOG_INFO("\nMy node id: %s\n", nodeId);

    BlockchainStatus status = executeBlockchainCommand("local", "(free.mesh03.get-my-node)");
    LOG_INFO("\nResponse: %s\n", blockchainStatusToString(status).c_str());

    uint32_t packetId = generatePacketId();
    String secret_hex = String(packetId, HEX);
    String secret_123 = "123";
    String secret = encrypt(director_pubkeyd_, secret_123.c_str());

    if (status == BlockchainStatus::READY) { // node exists, due for sending
        uint32_t packetId = generatePacketId();
        String secret_hex = String(packetId, HEX);
        String secret = encrypt(director_pubkeyd_, secret_hex.c_str());
        status = executeBlockchainCommand("send", "(free.mesh03.update-sent \"" + secret + "\")");
        if (status == BlockchainStatus::OK) {
            // Only send the radio beacon if the update-sent command is successful
            webAPI->sendSecret(packetId);
            LOG_INFO("\nUpdate sent successfully\n");
        } else {
            LOG_INFO("\nUpdate sent failed: %s\n", blockchainStatusToString(status).c_str());
        }
    } else if (status == BlockchainStatus::NODE_NOT_FOUND) { // node doesn't exist, insert it
        status = executeBlockchainCommand("send", "(free.mesh03.insert-my-node \"" + nodeId + "\")");
        LOG_INFO("\nNode insert local response: %s\n", blockchainStatusToString(status).c_str());
    } else if (status == BlockchainStatus::NOT_DUE) { // node exists, not due for sending
        LOG_INFO("\n%s\n", "DON'T SEND");
    } else {
        LOG_INFO("\nError occurred: %s\n", blockchainStatusToString(status).c_str());
    }
    auto newHeap = memGet.getFreeHeap();
    LOG_INFO("Free heap: %d\n", newHeap);
    return 300000; // Every 5 minutes. That should be enough for previous txn to be complete
}

struct HashVector {
    const char *name;
    const char *data;
    uint8_t hash[HASH_SIZE];
};

uint8_t *BlockchainHandler::Binhash(BLAKE2b *hash, const struct HashVector *test)
{
    size_t size = strlen(test->data);
    static uint8_t value[HASH_SIZE];

    hash->reset(32);
    hash->update(test->data, size);
    hash->finalize(value, sizeof(value));

    return value;
}

String BlockchainHandler::KDAhash(BLAKE2b *hash, const struct HashVector *test)
{
    size_t size = strlen(test->data);
    uint8_t value[HASH_SIZE];

    hash->reset(32);
    hash->update(test->data, size);
    hash->finalize(value, sizeof(value));

    auto inputLength = sizeof(value);
    char output[base64::encodeLength(inputLength)];
    base64::encode(value, inputLength, output);
    String hashString = String(output);
    hashString.replace("+", "-");
    hashString.replace("/", "_");
    hashString.replace("=", "");
    return hashString;
}

void BlockchainHandler::HexToBytes(const std::string &hex, char *out)
{
    for (unsigned int i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        char byte = (char)strtol(byteString.c_str(), NULL, 16);
        out[i / 2] = byte;
    }
}

String BlockchainHandler::generateSignature(const uint8_t *hashBin)
{
    char publicKey[32];
    HexToBytes(public_key_, publicKey);

    char privateKey[32];
    HexToBytes(private_key_, privateKey);

    uint8_t signature[64];
    Ed25519::sign(signature, (uint8_t *)privateKey, (uint8_t *)publicKey, hashBin, HASH_SIZE);

    // Convert bytes to hex string
    String signHex = "";
    for (uint8_t i = 0; i < sizeof(signature); i++) {
        signHex += String(signature[i] < 16 ? "0" : "") + String(signature[i], HEX);
    }
    return signHex;
}

JSONObject BlockchainHandler::createCommandObject(const String &command)
{
    JSONObject cmdObject;
    JSONArray signers;
    JSONObject signerObject = {
        {"scheme", new JSONValue("ED25519")}, {"pubKey", new JSONValue(public_key_)}, {"addr", new JSONValue(public_key_)}};
    signers.push_back(new JSONValue(signerObject));
    cmdObject["signers"] = new JSONValue(signers);

    JSONObject metaObject = {{"creationTime", new JSONValue((uint)getValidTime(RTCQualityFromNet))},
                             {"ttl", new JSONValue(28800)},
                             {"chainId", new JSONValue("19")},
                             {"gasPrice", new JSONValue(0.00001)},
                             {"gasLimit", new JSONValue(1000)},
                             {"sender", new JSONValue("k:" + public_key_)}};
    cmdObject["meta"] = new JSONValue(metaObject);

    String current_timestamp = getCurrentTimestamp();
    cmdObject["nonce"] = new JSONValue(current_timestamp.c_str());
    cmdObject["networkId"] = new JSONValue("mainnet01");

    JSONObject execObject = {
        {"code", new JSONValue(command.c_str())}, {"data", new JSONValue(JSONObject())} // Directly passing an empty JSONObject
    };
    JSONObject payloadObject = {{"exec", new JSONValue(execObject)}};
    cmdObject["payload"] = new JSONValue(payloadObject);

    return cmdObject;
}

JSONObject BlockchainHandler::preparePostObject(const JSONObject &cmdObject, const String &commandType)
{
    JSONObject postObject;

    JSONValue *cmd = new JSONValue(cmdObject);
    const String cmdString = cmd->Stringify().c_str();
    postObject["cmd"] = new JSONValue(cmdString.c_str());
    HashVector vector{"Test1", cmdString.c_str()};

    uint8_t *hashBin = Binhash(&blake2b_, &vector);
    String hash = KDAhash(&blake2b_, &vector);
    // LOG_INFO("\n%s\n", hash.c_str());

    // for (uint8_t i = 0; i < HASH_SIZE; i++) {
    //     LOG_INFO("%d,%d\n", i, hashBin[i]);
    // }

    String signHex = generateSignature(hashBin);
    postObject["hash"] = new JSONValue(hash.c_str());
    JSONArray sigs;
    JSONObject sigObject{{"sig", new JSONValue(signHex.c_str())}};
    sigs.push_back(new JSONValue(sigObject));
    postObject["sigs"] = new JSONValue(sigs);

    delete cmd;
    return postObject;
}

BlockchainStatus BlockchainHandler::parseBlockchainResponse(const String &response)
{
    BlockchainStatus returnStatus = BlockchainStatus::NODE_NOT_FOUND;
    JSONValue *response_value = JSON::Parse(response.c_str());
    if (response_value == nullptr) {
        return BlockchainStatus::PARSING_ERROR;
    }
    JSONObject responseObject = response_value->AsObject();
    JSONValue *result_value = responseObject["result"];
    JSONObject resultObject = result_value->AsObject();
    JSONValue *data_value = resultObject["data"];
    JSONValue *status_value = resultObject["status"];
    String status = status_value->Stringify().c_str();
    LOG_INFO("Status value: %s\n", status);
    if (status.startsWith("\"s")) {
        JSONObject dataRespObject = data_value->AsObject();
        JSONValue *pubkeyd_value = dataRespObject["pubkeyd"];
        director_pubkeyd_ = pubkeyd_value->AsString();
        LOG_INFO("Director PUBKEYD: %s\n", director_pubkeyd_.c_str());
        JSONValue *send_value = dataRespObject["send"];
        String sendValue = send_value->Stringify().c_str();
        if (sendValue == "true") {
            returnStatus = BlockchainStatus::READY;
        } else {
            returnStatus = BlockchainStatus::NOT_DUE;
        }
    }
    delete response_value;
    return returnStatus;
}

BlockchainStatus BlockchainHandler::executeBlockchainCommand(String commandType, String command)
{
    if (!isWifiAvailable()) {
        return BlockchainStatus::NO_WIFI;
    }
    HTTPClient http;
    http.begin(kda_server_ + commandType);
    http.addHeader("Content-Type", "application/json");

    JSONObject cmdObject = createCommandObject(command);
    JSONObject postObject = preparePostObject(cmdObject, commandType);

    JSONValue *post;
    if (commandType == "local") {
        post = new JSONValue(postObject);
    } else {
        JSONArray cmds;
        JSONObject cmdsObject;
        cmds.push_back(new JSONValue(postObject));
        cmdsObject["cmds"] = new JSONValue(cmds);
        post = new JSONValue(cmdsObject);
    }

    const String postRaw = post->Stringify().c_str();
    logLongString(postRaw);

    http.setTimeout(15000);
    int httpResponseCode = http.POST(postRaw);
    LOG_INFO("Kadena HTTP response %d\n", httpResponseCode);
    String response = http.getString();
    logLongString(response);

    http.end();
    delete post;
    LOG_INFO("Called HTTP end\n");
    // Handle HTTP response codes
    if (httpResponseCode < 0 || (httpResponseCode >= 400 && httpResponseCode <= 599)) {
        return BlockchainStatus::HTTP_ERROR;
    }
    if (httpResponseCode == HTTP_CODE_NO_CONTENT) {
        return BlockchainStatus::EMPTY_RESPONSE;
    }

    if (commandType == "local") {
        return parseBlockchainResponse(response);
    } else {
        return BlockchainStatus::OK;
    }
}

// Function to add PKCS7 padding
void add_pkcs7_padding(std::vector<unsigned char>& data, size_t block_size) {
    size_t padding_size = block_size - (data.size() % block_size);
    data.insert(data.end(), padding_size, static_cast<unsigned char>(padding_size));
}

bool derive_key_iv_pbkdf2(const std::string& password, const unsigned char *salt, size_t salt_len, unsigned char *key, size_t key_len, unsigned char *iv, size_t iv_len, int iterations) {
    mbedtls_md_context_t md_ctx;
    mbedtls_md_type_t md_type = MBEDTLS_MD_SHA256; // More secure than MD5

    mbedtls_md_init(&md_ctx);
    if (mbedtls_md_setup(&md_ctx, mbedtls_md_info_from_type(md_type), 1) != 0) {
        std::cerr << "Failed to setup md context for PBKDF2" << std::endl;
        mbedtls_md_free(&md_ctx);
        return false;
    }

    unsigned char key_iv[key_len + iv_len];  // Buffer to hold both key and IV
    int ret = mbedtls_pkcs5_pbkdf2_hmac(&md_ctx, reinterpret_cast<const unsigned char*>(password.data()), password.size(), salt, salt_len, iterations, sizeof(key_iv), key_iv);
    if (ret != 0) {
        std::cerr << "Failed to derive key+IV using PBKDF2" << std::endl;
        mbedtls_md_free(&md_ctx);
        return false;
    }

    // Copy the derived data into key and IV buffers
    memcpy(key, key_iv, key_len);
    memcpy(iv, key_iv + key_len, iv_len);

    mbedtls_md_free(&md_ctx);
    return true;
}

String BlockchainHandler::encrypt(const std::string &base64PublicKey, const std::string &payload) {
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
    const unsigned char* publicKey = reinterpret_cast<const unsigned char*>(decodedKey.c_str());
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
    if (mbedtls_rsa_rsaes_oaep_encrypt(rsa, mbedtls_ctr_drbg_random, &ctr_drbg, MBEDTLS_RSA_PUBLIC, nullptr, 0, sizeof(symKeyHex), reinterpret_cast<const unsigned char*>(symKeyHex), buffer) != 0) {
        LOG_ERROR("RSA encryption failed\n");
        return "";
    }
    olen = mbedtls_rsa_get_len(rsa);

    // Encrypt the payload using AES
    // unsigned char iv[16];
    // mbedtls_ctr_drbg_random(&ctr_drbg, iv, sizeof(iv));

    // Generate a random 8-byte salt
    unsigned char salt[8];
    mbedtls_ctr_drbg_random(&ctr_drbg, salt, sizeof(salt));
    unsigned char key[32], iv[16];
    std::string symKeyString = std::string(symKeyHex);
    LOG_INFO("KEY: %s\n", symKeyString.c_str());
    if (!derive_key_iv_pbkdf2(symKeyString, salt, 8, key, 32, iv, 16, 1000)) {
        std::cerr << "Key and IV derivation failed." << std::endl;
    }
    // Convert and log the IV in hexadecimal format
    std::string ivHex;
    for (unsigned char byte : std::vector<unsigned char>(iv, iv + sizeof(iv))) {
        char hex[3]; // Temporary buffer for each byte
        sprintf(hex, "%02x", byte);
        ivHex += hex; // Append the hex string to the result
    }
    LOG_INFO("IV: %s\n", ivHex.c_str());
    // Set key length to 256 bits
    mbedtls_aes_setkey_enc(&aes, /*reinterpret_cast<const unsigned char*>(aesKeyHex)*/key, 256);  // Using 256-bit encryption key

    // Add PKCS7 padding to the payload
    std::vector<unsigned char> paddedPayload(payload.begin(), payload.end());
    add_pkcs7_padding(paddedPayload, 16);

    // Encrypt the payload using AES-CBC
    std::vector<unsigned char> encryptedData(paddedPayload.size());
    mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT, paddedPayload.size(), iv, paddedPayload.data(), encryptedData.data());
    // Convert and log the salt in hexadecimal format
    std::string saltHex;
    for (unsigned char byte : std::vector<unsigned char>(salt, salt + sizeof(salt))) {
        char hex[3]; // Temporary buffer for each byte
        sprintf(hex, "%02x", byte);
        saltHex += hex; // Append the hex string to the result
    }
    LOG_INFO("Salt: %s\n", saltHex.c_str());

    std::string encryptedDataHex;
    for (unsigned char byte : encryptedData) {
        char hex[3]; // Temporary buffer for each byte
        sprintf(hex, "%02x", byte);
        encryptedDataHex += hex; // Append the hex string to the result
    }
    LOG_INFO("Encrypted Data: %s\n", encryptedDataHex.c_str());

    // Combine prefix, salt and encryptedData
    std::vector<unsigned char> combinedData;
    const char* prefix = "Salted__";
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
    LOG_INFO("+++++++++ Encrypted combined Data Base64: %s\n", encryptedCombinedDataStr.c_str());
    LOG_INFO("+++++++++ Encrypted SymKey Base64: %s\n", encryptedKeyStr.c_str());
    LOG_INFO("+++++++++ RESULT OF ENCRYPT!!!: %s\n", result.c_str());
    logLongString(result);

    // Cleanup
    mbedtls_aes_free(&aes);
    mbedtls_pk_free(&pk);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);

    return result;
}
#endif
