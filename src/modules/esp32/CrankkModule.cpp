#include "configuration.h"
#if defined(ARCH_ESP32) && !MESHTASTIC_EXCLUDE_CRANKK
#include "CrankkModule.h"
#include "MeshService.h"
#include "NodeDB.h"
#include "PowerFSM.h"
#include "mesh/blockchain/BlockchainHandler.h"

CrankkModule *crankkModule;

ProcessMessage CrankkModule::handleReceived(const meshtastic_MeshPacket &mp)
{
#ifdef DEBUG_PORT
    auto &p = mp.decoded;
    LOG_INFO("Received crankk msg from=0x%0x, id=0x%x, msg=%.*s\n", mp.from, mp.id, p.payload.size, p.payload.bytes);
#endif

    String message = "";
    char msg[237];
    sprintf(msg, "%s", p.payload.bytes);
    message += msg;
    LOG_INFO("\nCrankk message received: %s\n", message);

    String nodeId = String(mp.from, HEX);
    LOG_INFO("\nFrom node id: %s\n", nodeId);
    if (message == "CR24" && nodeId != "0") {
        LOG_INFO("\nCrankk message received: %s\n", message);

        std::unique_ptr<BlockchainHandler> blockchainHandler(
            new BlockchainHandler(moduleConfig.wallet.public_key, moduleConfig.wallet.private_key));

        // Get the director's public key in order to perform the encryption
        String get_key_command = "(free.mesh03.get-sender-details \"" + nodeId + "\")";
        BlockchainStatus status_local = blockchainHandler->executeBlockchainCommand("local", get_key_command);
        LOG_INFO("\nStatus 'get-sender-details': %s\n", blockchainHandler->blockchainStatusToString(status_local).c_str());
        if (status == BlockchainStatus::SUCCESS) {
            String packetId = String(mp.id, HEX);
            String secret = blockchainHandler->encryptPayload(packetId.c_str());
            String received_chain_command = "(free.mesh03.add-received-with-chain \"" + nodeId + "\" \"" + secret + "\" \"19\")";
            BlockchainStatus status_send = blockchainHandler->executeBlockchainCommand("send", received_chain_command);
            LOG_INFO("\nStatus 'add-received-with-chain': %s\n",
                     blockchainHandler->blockchainStatusToString(status_send).c_str());
        } else {
            LOG_INFO("\nError occurred: %s\n", blockchainHandler->blockchainStatusToString(status).c_str());
        }
    }

    // We only store/display messages destined for us.
    // Keep a copy of the most recent text message.
    // devicestate.rx_text_message = mp;
    // devicestate.has_rx_text_message = true;

    // powerFSM.trigger(EVENT_RECEIVED_MSG);
    // notifyObservers(&mp);

    return ProcessMessage::CONTINUE; // Let others look at this message also if they want
}

bool CrankkModule::wantPacket(const meshtastic_MeshPacket *p)
{
    return p->decoded.portnum == meshtastic_PortNum_CRANKK_APP;
    // return MeshService::isTextPayload(p);
}
#endif