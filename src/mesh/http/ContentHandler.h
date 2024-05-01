#pragma once
/*
  Including the esp32_https_server library will trigger a compile time error. I've
  tracked it down to a reoccurrance of this bug:
    https://gcc.gnu.org/bugzilla/show_bug.cgi?id=57824
  The work around is described here:
    https://forums.xilinx.com/t5/Embedded-Development-Tools/Error-with-Standard-Libaries-in-Zynq/td-p/450032

  Long story short is we need "#undef str" before including the esp32_https_server.
    - Jm Casler (jm@casler.org) Oct 2020
*/
#undef str

// Includes for the https server
//   https://github.com/fhessel/esp32_https_server
#include <HTTPRequest.hpp>
#include <HTTPResponse.hpp>
#include <HTTPSServer.hpp>
#include <HTTPServer.hpp>
#include <SSLCert.hpp>

void registerHandlers(httpsserver::HTTPServer *insecureServer, httpsserver::HTTPSServer *secureServer);

// Declare some handler functions for the various URLs on the server
void handleAPIv1FromRadio(httpsserver::HTTPRequest *req, httpsserver::HTTPResponse *res);
void handleAPIv1ToRadio(httpsserver::HTTPRequest *req, httpsserver::HTTPResponse *res);
void handleHotspot(httpsserver::HTTPRequest *req, httpsserver::HTTPResponse *res);
void handleStatic(httpsserver::HTTPRequest *req, httpsserver::HTTPResponse *res);
void handleRestart(httpsserver::HTTPRequest *req, httpsserver::HTTPResponse *res);
void handleFormUpload(httpsserver::HTTPRequest *req, httpsserver::HTTPResponse *res);
void handleScanNetworks(httpsserver::HTTPRequest *req, httpsserver::HTTPResponse *res);
void handleFsBrowseStatic(httpsserver::HTTPRequest *req, httpsserver::HTTPResponse *res);
void handleFsDeleteStatic(httpsserver::HTTPRequest *req, httpsserver::HTTPResponse *res);
void handleBlinkLED(httpsserver::HTTPRequest *req, httpsserver::HTTPResponse *res);
void handleReport(httpsserver::HTTPRequest *req, httpsserver::HTTPResponse *res);
void handleUpdateFs(httpsserver::HTTPRequest *req, httpsserver::HTTPResponse *res);
void handleDeleteFsContent(httpsserver::HTTPRequest *req, httpsserver::HTTPResponse *res);
void handleFs(httpsserver::HTTPRequest *req, httpsserver::HTTPResponse *res);
void handleAdmin(httpsserver::HTTPRequest *req, httpsserver::HTTPResponse *res);
void handleAdminSettings(httpsserver::HTTPRequest *req, httpsserver::HTTPResponse *res);
void handleAdminSettingsApply(httpsserver::HTTPRequest *req, httpsserver::HTTPResponse *res);

// Interface to the PhoneAPI to access the protobufs with messages
class HttpAPI : public PhoneAPI
{

  public:
    // Nothing here yet

  private:
    // Nothing here yet

  protected:
    /// Check the current underlying physical link to see if the client is currently connected
    virtual bool checkIsConnected() override { return true; } // FIXME, be smarter about this
};