#pragma once
#include "BLAKE2b.h"
#include "NodeDB.h"
#include "RTC.h"
#include "Router.h"
#include "concurrency/Periodic.h"
#include "configuration.h"
#include "mesh/NodeDB.h"
#include "mesh/http/ContentHandler.h"
#include "mqtt/JSON.h"
#include "target_specific.h"
#include <Crypto.h>
#include <memory>
#include <string.h>
#include <string>
#if defined(ESP8266) || defined(ESP32)
#include <pgmspace.h>
#else
#include <avr/pgmspace.h>
#endif
#include "Ed25519.h"
#include "arduino_base64.hpp"

#define HASH_SIZE 32

class BlockchainHandler
{
  public:
    /**
     * Initializes a new instance of the BlockchainHandler class with specified public and private keys.
     *
     * @param public_key The public key to be used for blockchain operations.
     * @param private_key The private key to be used for blockchain operations.
     */
    BlockchainHandler(const std::string public_key, const std::string private_key);

    /**
     * Destructor for the BlockchainHandler class.
     */
    ~BlockchainHandler() = default;
    ;

    /**
     * Initiates a synchronization process with the blockchain, executing required actions based on the node's current state.
     *
     * This method is responsible for ensuring the node's data is up-to-date with the blockchain by performing synchronization
     * tasks. It may involve sending or receiving data to/from the blockchain, depending on the node's status.
     *
     * @param webAPI The HttpAPI instance used to call sendSecret()
     * @return The interval in milliseconds before the next synchronization attempt should occur.
     */
    int32_t performNodeSync(HttpAPI *webAPI);

    /**
     * Executes a specified command on a blockchain web service.
     *
     * This method sends a command to a blockchain-related web service and retrieves the response.
     * It is used to interact with blockchain operations through web service APIs.
     *
     * @param commandType Identifies the web service for the call.
     * @param command Specifies the blockchain command for execution on the web service.
     * @return A String object containing the response received from the web service after executing the command.
     */
    String executeBlockchainCommand(String commandType, String command);

  private:
    /**
     * Checks if the wallet configuration is valid.
     *
     * This method verifies if the wallet is enabled and both the public and private keys are of the correct length.
     *
     * @return True if the wallet configuration is valid, otherwise false.
     */
    bool isWalletConfigValid();

    /**
     * Generates a binary hash from the given HashVector.
     *
     * @param hash A pointer to the BLAKE2b object.
     * @param test A pointer to the HashVector containing the data to hash.
     * @return A pointer to the resulting binary hash.
     */
    uint8_t *Binhash(BLAKE2b *hash, const struct HashVector *test);

    /**
     * Generates a Kadena hash from the given HashVector.
     *
     * @param hash A pointer to the BLAKE2b object.
     * @param test A pointer to the HashVector containing the data to hash.
     * @return A String containing the Kadena hash.
     */
    String KDAhash(BLAKE2b *hash, const struct HashVector *test);

    /**
     * Converts a hexadecimal string to a byte array.
     *
     * @param hex The hexadecimal string to convert.
     * @param out A pointer to the output byte array.
     */
    void HexToBytes(const std::string &hex, char *out);

    /**
     * Generates a digital signature for a given binary hash.
     *
     * This method takes a binary hash as input and generates a digital signature using the private key associated with the
     * blockchain handler. The signature is used to authenticate transactions or data when interacting with the blockchain.
     *
     * @param hashBin A pointer to the binary hash that needs to be signed.
     * @return A String containing the hexadecimal representation of the digital signature.
     */
    String generateSignature(const uint8_t *hashBin);

    /**
     * Creates a JSON object representing a blockchain command.
     *
     * This method constructs a JSON object that encapsulates the details of a blockchain command,
     * including the command itself and associated metadata required for its execution.
     *
     * @param command The blockchain command to be executed.
     * @return A JSONObject representing the command to be sent to the blockchain.
     */
    JSONObject createCommandObject(const String &command);

    /**
     * Prepares a JSON object for POST request based on the command object and command type.
     *
     * This method prepares a JSON object that is ready to be sent as a POST request to the blockchain.
     * It includes the command object and additional information based on the command type.
     *
     * @param cmdObject The command object created by createCommandObject.
     * @param commandType The type of the command, affecting how the post object is prepared.
     * @return A JSONObject ready for being sent as a POST request.
     */
    JSONObject preparePostObject(const JSONObject &cmdObject, const String &commandType);

    /**
     * Parses the blockchain response received as a string into a more usable form.
     *
     * This method takes a blockchain response in the form of a string, parses it, and extracts
     * relevant information, making it easier to handle the response programmatically.
     *
     * @param response The blockchain response as a raw string.
     * @return A String representing the parsed and possibly simplified response.
     */
    String parseBlockchainResponse(const String &response);

    std::string public_key_;
    std::string private_key_;
    String kda_server_;
    BLAKE2b blake2b_;
};