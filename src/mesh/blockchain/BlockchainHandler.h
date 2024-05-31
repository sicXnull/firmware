#pragma once
#include "EncryptionHandler.h"
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

// Define an enumeration for status codes
enum class BlockchainStatus {
    SUCCESS,
    FAILURE,
    NO_WIFI,
    HTTP_ERROR,
    EMPTY_RESPONSE,
    PARSING_ERROR,
    NODE_NOT_FOUND,
    READY,
    NOT_DUE,
    // Add more specific status codes as needed
};

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
     * @return A BlockchainStatus enumeration value indicating the result of the command execution.
     */
    BlockchainStatus executeBlockchainCommand(String commandType, String command);

    /**
     * Encrypts a payload.
     *
     * This method encrypts the provided payload using the director's public key.
     * The encryption process involves generating a symmetric key, encrypting the payload with AES,
     * and then encrypting the symmetric key with RSA.
     *
     * @param payload The data to be encrypted.
     * @return A string containing the encrypted payload.
     */
    String encryptPayload(const std::string &payload);

    /**
     * Converts a BlockchainStatus enum value to its corresponding string representation.
     *
     * This method takes a BlockchainStatus enum value and returns a human-readable string
     * that represents the status. This is useful for logging, debugging, or displaying
     * the status in a user interface.
     *
     * @param status The BlockchainStatus enum value to be converted.
     * @return A string representation of the given BlockchainStatus.
     */
    std::string blockchainStatusToString(BlockchainStatus status);

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
     * The method first attempts to parse the response string into a JSON object. If the parsing
     * fails, it returns a PARSING_ERROR status. It then examines the "result" field of the JSON
     * object to determine the status of the blockchain command. Depending on the command type,
     * it extracts specific information such as the director's public key and the send status.
     *
     * @param response The blockchain response as a raw string.
     * @param command The blockchain command that was executed, used to determine the context of the response.
     * @return A BlockchainStatus enum value representing the status of the parsed response.
     */
    BlockchainStatus parseBlockchainResponse(const String &response, const String &command);

    std::string public_key_;
    std::string private_key_;
    String kda_server_;
    std::string director_pubkeyd_;
    std::unique_ptr<EncryptionHandler> encryptionHandler_;
};