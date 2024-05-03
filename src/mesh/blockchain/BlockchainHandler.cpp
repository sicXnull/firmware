#if !MESHTASTIC_EXCLUDE_WEBSERVER
#include "BlockchainHandler.h"
#include "FSCommon.h"
#include "HTTPClient.h"
#include "WiFi.h"
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

    String resp = executeBlockchainCommand("local", "(free.mesh03.get-my-node)");
    LOG_INFO("\nResponse: %s\n", resp.c_str());

    if (resp == "true") { // node exists, due for sending
        uint32_t packetId = generatePacketId();
        webAPI->sendSecret(packetId);
        executeBlockchainCommand("send", "(free.mesh03.update-sent \"" + String(packetId, HEX) + "\")");
    } else if (resp.startsWith("no")) { // node doesn't exist, insert it
        resp = executeBlockchainCommand("send", "(free.mesh03.insert-my-node \"" + nodeId + "\")");
        LOG_INFO("\nNode insert local response: %s\n", resp);
    } else { // node exists, not due for sending
        LOG_INFO("\n%s\n", "DON'T SEND");
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

String BlockchainHandler::parseBlockchainResponse(const String &response)
{
    String sendValue = "false";
    JSONValue *response_value = JSON::Parse(response.c_str());
    JSONObject responseObject = response_value->AsObject();
    JSONValue *result_value = responseObject["result"];
    JSONObject resultObject = result_value->AsObject();
    JSONValue *data_value = resultObject["data"];
    JSONValue *status_value = resultObject["status"];
    String status = status_value->Stringify().c_str();
    LOG_INFO("Status value: %s\n", status);
    if (status.startsWith("\"s")) {
        JSONObject dataRespObject = data_value->AsObject();
        JSONValue *send_value = dataRespObject["send"];
        sendValue = send_value->Stringify().c_str();
    } else {
        sendValue = "no node";
    }
    delete response_value;
    LOG_INFO("Send value before return: %s\n", sendValue);
    return sendValue;
}

String BlockchainHandler::executeBlockchainCommand(String commandType, String command)
{
    if (!isWifiAvailable()) {
        return "No wifi";
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
    if (httpResponseCode < 0)
        return "";

    if (commandType == "local") {
        String sendValue = parseBlockchainResponse(response);
        return sendValue;
    } else {
        return response.c_str();
    }
}
#endif