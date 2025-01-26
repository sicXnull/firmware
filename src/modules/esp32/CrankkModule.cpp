#include "configuration.h"
#if defined(ARCH_ESP32) && !MESHTASTIC_EXCLUDE_CRANKK
#include "CrankkModule.h"
#include "MeshService.h"
#include "NodeDB.h"
#include "PowerFSM.h"

CrankkModule *crankkModule;

void CrankkModule::initializeBlockchainHandler()
{
    if (moduleConfig.wallet.enabled && moduleConfig.wallet.public_key && moduleConfig.wallet.private_key) {
        blockchainHandler = std::unique_ptr<BlockchainHandler>(
            new BlockchainHandler(moduleConfig.wallet.public_key, moduleConfig.wallet.private_key, moduleConfig.wallet.enabled));
        LOG_INFO("Blockchain handler initialized with wallet: %s\n", moduleConfig.wallet.public_key);
    } else {
        LOG_WARN("Blockchain handler disabled - invalid wallet config\n");
    }
}

ProcessMessage CrankkModule::handleReceived(const meshtastic_MeshPacket &mp)
{
#ifdef DEBUG_PORT
    auto &p = mp.decoded;
    LOG_DEBUG("Received crankk msg from=0x%0x, id=0x%x, msg=%.*s\n", mp.from, mp.id, p.payload.size, p.payload.bytes);
#endif

    String message = "";
    char msg[237];
    sprintf(msg, "%s", p.payload.bytes);
    message += msg;
    LOG_DEBUG("\nCrankk message received: %s\n", message);

    String nodeId = String(mp.from, HEX);
    LOG_DEBUG("\nFrom node id: %s\n", nodeId);

    if (!blockchainHandler) {
        LOG_ERROR("Blockchain handler not initialized - check wallet config\n");
        return ProcessMessage::CONTINUE;
    }

    if (message == "CR24" && nodeId != "0") {
        handleCR24(mp, nodeId);
    }
    // Example message format for transfers:
    // "TRANSFER:<receiver_addr>:<amount>:<token_contract>"
    else if (message.startsWith("TRANSFER:")) {
        handleTransferCommand(message);
    }
    // Add other message handlers here

    // We only store/display messages destined for us.
    // Keep a copy of the most recent text message.
    // devicestate.rx_text_message = mp;
    // devicestate.has_rx_text_message = true;

    // powerFSM.trigger(EVENT_RECEIVED_MSG);
    // notifyObservers(&mp);

    return ProcessMessage::CONTINUE; // Let others look at this message also if they want
}

void CrankkModule::handleCR24(const meshtastic_MeshPacket &mp, const String &nodeId)
{
    // Get the director's public key in order to perform the encryption
    String get_key_command = "(free.mesh03.get-sender-details \"" + nodeId + "\")";
    BlockchainStatus status_local = blockchainHandler->executeBlockchainCommand("local", get_key_command);
    LOG_DEBUG("\nStatus 'get-sender-details': %s\n", blockchainHandler->blockchainStatusToString(status_local).c_str());
    if (status_local == BlockchainStatus::SUCCESS) {
        String packetId = String(mp.id, HEX);
        String secret = blockchainHandler->encryptPayload(packetId.c_str());
        String received_chain_command = "(free.mesh03.add-received-with-chain \"" + nodeId + "\" \"" + secret + "\" \"19\")";
        BlockchainStatus status_send = blockchainHandler->executeBlockchainCommand("send", received_chain_command);
        LOG_DEBUG("\nStatus 'add-received-with-chain': %s\n", blockchainHandler->blockchainStatusToString(status_send).c_str());
    } else {
        LOG_DEBUG("\nError occurred: %s\n", blockchainHandler->blockchainStatusToString(status_local).c_str());
    }
}

void CrankkModule::handleTransferCommand(const String &message)
{
    // Example message format: "TRANSFER:<receiver>:<amount>:<contract>"
    String params = message.substring(9);
    int firstColon = params.indexOf(':');
    int secondColon = params.indexOf(':', firstColon + 1);

    String receiver = params.substring(0, firstColon);
    String amount = params.substring(firstColon + 1, secondColon);
    String contract = params.substring(secondColon + 1);

    blockchainHandler->executeTransfer(receiver, amount, contract);
}

bool CrankkModule::wantPacket(const meshtastic_MeshPacket *p)
{
    return p->decoded.portnum == meshtastic_PortNum_CRANKK_APP;
    // return MeshService::isTextPayload(p);
}

#endif
