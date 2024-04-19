#include "BlockchainHandler.h"
#include "FSCommon.h"
#include "HTTPClient.h"
#include <memory>
#include <fstream>


BlockchainHandler::BlockchainHandler(const std::string public_key, const std::string private_key): public_key_(public_key), private_key_(private_key)
{
    //kda_server_ = "http://staging.mishocy.io:1848/chainweb/0.0/mainnet01/chain/19/pact/api/v1/";
    kda_server_ = "http://kda.crankk.org/chainweb/0.0/mainnet01/chain/19/pact/api/v1/";
}

BlockchainHandler::~BlockchainHandler() {
    //stopPeriodicCall();
}

// void BlockchainHandler::startPeriodicCall() {
//     if (!periodic_task_) {
//          // For this implementation, Periodic needs to be adapted to accept a std::function<int32>
//         periodic_task_.reset(new concurrency::Periodic("BlockchainTask",
//             [this]() -> int32_t {
//                 return this->performNodeSync();
//             }));
//     }
// }

// void BlockchainHandler::stopPeriodicCall() {
//     if (periodic_task_) {
//         periodic_task_.reset();
//     }
// }

int32_t BlockchainHandler::performNodeSync() {
    LOG_INFO("\nWallet public key: %s\n", public_key_.data());
    LOG_INFO("\nWallet private key: %s\n", private_key_.data());

    // String nodeId = "";
    // char nodeIdHex[8];
    // sprintf(nodeIdHex, "%08x", nodeDB->getNodeNum());
    //nodeId += nodeIdHex;
    String nodeId = String(nodeDB->getNodeNum(), HEX);
    nodeId.toUpperCase(); // Ensure the hex string is uppercase if needed
    LOG_INFO("\nMy node id: %s\n", nodeId);
    // if (/*!moduleConfig.wallet.enabled ||*/ public_key_.length() < 64 || private_key_.length() < 64) {
    //     return 300000; //Every 5 minutes.
    // }

    String resp = executeBlockchainCommand("local", "(free.mesh03.get-my-node)");
    //LOG_INFO("\nResponse: %s\n", resp.c_str());
    return 10000;

    if (resp == "true") { //node exists, due for sending
        if (getValidTime(RTCQualityFromNet) > 0) {
           // HttpAPI webAPI;
            //webAPI.sendSecret();
            executeBlockchainCommand("send","(free.mesh03.update-sent \"123123\")");
        }
    } else if (resp.startsWith("no")) { //node doesn't exist, insert it
        if (getValidTime(RTCQualityFromNet) > 0) {
            resp = executeBlockchainCommand("send","(free.mesh03.insert-my-node \"" + nodeId + "\")");
            LOG_INFO("\nNode insert local response: %s\n", resp);
        }
    } else { //node exists, not due for sending
        LOG_INFO("\n%s\n", "DON'T SEND");
    }
    return 300000; //Every 5 minutes. That should be enough for previous txn to be complete
}

struct HashVector
{
    const char *name;
    const char *data;
    uint8_t hash[HASH_SIZE];
};

uint8_t* BlockchainHandler::Binhash(Hash *hash, const struct HashVector *test)
{
    size_t size = strlen(test->data);
    static uint8_t value[HASH_SIZE];

    hash->reset();
    hash->update(test->data, size);
    hash->finalize(value, sizeof(value));

    return value;
}

String BlockchainHandler::KDAhash(Hash *hash, const struct HashVector *test)
{
    size_t size = strlen(test->data);
    uint8_t value[HASH_SIZE];

    hash->reset();
    hash->update(test->data, size);
    hash->finalize(value, sizeof(value));

    // LOG_INFO("\n");
    // for (uint8_t i = 0; i < sizeof(value); i++) {
    //     LOG_INFO("%d,%d,%x\n", i, value[i], value[i]);
    // }
    // LOG_INFO("\n");

    auto inputLength = sizeof(value);
    char output[base64::encodeLength(inputLength)];
    base64::encode(value, inputLength, output);
    LOG_INFO("\n%s\n", output);
    String hashString = String(output);
    LOG_INFO("\n%s\n", hashString.c_str());
    hashString.replace("+","-");
    hashString.replace("/","_");
    hashString.replace("=","");
    return hashString;
}

void BlockchainHandler::HexToBytes(const std::string& hex, char* out)
{
  for (unsigned int i = 0; i < hex.length(); i += 2) {
    std::string byteString = hex.substr(i, 2);
    char byte = (char) strtol(byteString.c_str(), NULL, 16);
    out[i/2] = byte;
  }
}

String BlockchainHandler::generateSignature(const uint8_t* hashBin) {
    char publicKey[32];
    HexToBytes(public_key_, publicKey);

    char privateKey[32];
    HexToBytes(private_key_, privateKey);

    uint8_t signature[64];
    Ed25519::sign(signature, (uint8_t*)privateKey, (uint8_t*)publicKey, hashBin, HASH_SIZE);

    // char byteHex[2];
    // String signHex = "";
    // for (uint8_t i = 0; i < sizeof(signature); i++) {
    //     sprintf(byteHex, "%02x", signature[i]);
    //     signHex += byteHex;
    // }
    // Use a more direct approach to convert bytes to hex string
    String signHex;
    signHex.reserve(sizeof(signature) * 2); // Pre-allocate memory to avoid reallocations
    for (uint8_t i = 0; i < sizeof(signature); i++) {
        signHex += String(signature[i] >> 4, HEX);
        signHex += String(signature[i] & 0xF, HEX);
    }
    return signHex;
}

JSONObject BlockchainHandler::createCommandObject(const String& command) {
    JSONObject cmdObject;
    JSONArray signers;
    JSONObject signerObject = {
        {"scheme", new JSONValue("ED25519")},
        {"pubKey", new JSONValue(public_key_)},
        {"addr", new JSONValue(public_key_)}
    };
    signers.push_back(new JSONValue(signerObject));
    cmdObject["signers"] = new JSONValue(signers);

    JSONObject metaObject = {
        {"creationTime", new JSONValue(getValidTime(RTCQualityFromNet))},
        {"ttl", new JSONValue(28800)},
        {"chainId", new JSONValue("19")},
        {"gasPrice", new JSONValue(0.00001)},
        {"gasLimit", new JSONValue(1000)},
        {"sender", new JSONValue("k:" + public_key_)}
    };
    cmdObject["meta"] = new JSONValue(metaObject);

    cmdObject["nonce"] = new JSONValue("2024-04-03 01:16:49.647 UTC");
    cmdObject["networkId"] = new JSONValue("mainnet01");

    JSONObject execObject = {
        {"code", new JSONValue(command.c_str())},
        {"data", new JSONValue(JSONObject())} // Directly passing an empty JSONObject
    };
    JSONObject payloadObject = {{"exec", new JSONValue(execObject)}};
    cmdObject["payload"] = new JSONValue(payloadObject);

    return cmdObject;
}

JSONObject BlockchainHandler::preparePostObject(const JSONObject& cmdObject, const String& commandType) {
    JSONObject postObject;
    HashVector vector{"Test1", (new JSONValue(cmdObject))->Stringify().c_str()};

    postObject["cmd"] = new JSONValue(vector.data);

    uint8_t *hashBin = Binhash(&blake2b_, &vector);
    String hash = KDAhash(&blake2b_, &vector);
    LOG_INFO("\n%s\n", hash.c_str());

    for (uint8_t i = 0; i < HASH_SIZE; i++) {
        LOG_INFO("%d,%d\n", i, hashBin[i]);
    }

    String signHex = generateSignature(hashBin);
    postObject["hash"] = new JSONValue(hash);
    JSONArray sigs;
    JSONObject sigObject{{"sig", new JSONValue(signHex)}};
    sigs.push_back(new JSONValue(sigObject));
    postObject["sigs"] = new JSONValue(sigs);

    return postObject;
}

String BlockchainHandler::parseBlockchainResponse(const String& response) {
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
    LOG_INFO("Send value before return: %s\n", sendValue);
    return sendValue;
}

String BlockchainHandler::executeBlockchainCommand(String commandType, String command)
{
    HTTPClient http;
    http.begin(kda_server_+commandType);
    http.addHeader("Content-Type", "application/json");
    //int httpResponseCode = http.GET();
    JSONObject cmdObject = createCommandObject(command);
    uint8_t dmac[6];
    getMacAddr(dmac);

    JSONObject postObject = preparePostObject(cmdObject, commandType);

    JSONArray cmds;
    JSONObject cmdsObject;
    cmds.push_back(new JSONValue(postObject));
    cmdsObject["cmds"] = new JSONValue(cmds);

    JSONValue *post = commandType == "local" ? new JSONValue(postObject) : new JSONValue(cmdsObject);

    const String postRaw = post->Stringify().c_str();
    if (postRaw.length() > 50) {
        for (int i = 0; i < postRaw.length(); i += 50) {
            if (i + 50 < postRaw.length()) {
                LOG_INFO("%s\n", postRaw.substring(i, i + 50).c_str());
            } else {
                LOG_INFO("%s\n", postRaw.substring(i, postRaw.length()).c_str());
            }
        }
    }

    //LOG_INFO("%s\n", postRaw.c_str());

    //int httpResponseCode = http.POST(postRaw);
    //LOG_INFO("Kadena HTTP response %d\n", httpResponseCode);
    String response = http.getString();
    if (response.length() > 50) {
        for (int i = 0; i < response.length(); i += 50) {
            if (i + 50 < response.length()) {
                LOG_INFO("%s\n", response.substring(i, i + 50).c_str());
            } else {
                LOG_INFO("%s\n", response.substring(i, response.length()).c_str());
            }
        }
    }
    http.end();

    return response.c_str();

    if (commandType == "local") {
        String sendValue = parseBlockchainResponse(response);
        return sendValue;
    } else {
        return response.c_str();
    }
    LOG_INFO("%02X:%02X:%02X:%02X:%02X:%02X", dmac[0], dmac[1], dmac[2], dmac[3], dmac[4], dmac[5]);
    //64:B7:08:B8:D1:C8 other
    //00:B7:08:B8:D4:D0
}