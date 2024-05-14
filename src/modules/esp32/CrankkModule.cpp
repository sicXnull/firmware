#if defined(ARCH_ESP32) && !MESHTASTIC_EXCLUDE_WEBSERVER
#include "CrankkModule.h"
#include "MeshService.h"
#include "NodeDB.h"
#include "PowerFSM.h"
#include "configuration.h"
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
        std::unique_ptr<BlockchainHandler> blockchainHandler(
            new BlockchainHandler(moduleConfig.wallet.public_key, moduleConfig.wallet.private_key));
        LOG_INFO("\nCrankk message received: %s\n", message);

        String packetId = String(mp.id, HEX);
        String command = "(free.mesh03.add-received-with-chain \"" + nodeId + "\" \"" + packetId + "\" \"19\")";
        blockchainHandler->executeBlockchainCommand("send", command);
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