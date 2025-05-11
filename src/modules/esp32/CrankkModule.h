#pragma once
#include "Observer.h"
#include "SinglePortModule.h"
#include <BlockchainHandler.h>

/**
 * Text message handling for meshtastic - draws on the OLED display the most recent received message
 */
class CrankkModule : public SinglePortModule, public Observable<const meshtastic_MeshPacket *>
{
  public:
    /** Constructor
     * name is for debugging output
     */
    CrankkModule() : SinglePortModule("crankk", meshtastic_PortNum_TEXT_MESSAGE_APP) { initializeBlockchainHandler(); }

  protected:
    std::unique_ptr<BlockchainHandler> blockchainHandler_;
    void initializeBlockchainHandler();
    void handleTransferCommand(const String &message);
    void handleCR24(const meshtastic_MeshPacket &mp, const String &nodeId);

    /** Called to handle a particular incoming message

    @return ProcessMessage::STOP if you've guaranteed you've handled this message and no other handlers should be considered for
    it
    */
    virtual ProcessMessage handleReceived(const meshtastic_MeshPacket &mp) override;
    virtual bool wantPacket(const meshtastic_MeshPacket *p) override;
};

extern CrankkModule *crankkModule;