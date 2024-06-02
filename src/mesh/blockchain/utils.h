#pragma once
#include "configuration.h"
#include <ctime>
#include <iomanip>
#include <sstream>

// Function to get the current timestamp
inline String getCurrentTimestamp()
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

// Logging utility function to avoid 50 char limitation
inline void logLongString(const String &str, size_t chunkSize = 50)
{
    size_t len = str.length();
    if (len <= chunkSize) {
        LOG_DEBUG("%s\n", str.c_str());
    } else {
        size_t i = 0;
        while (i < len) {
            size_t end = std::min(i + chunkSize, len);
            LOG_DEBUG("%s\n", str.substring(i, end).c_str());
            i = end;
        }
    }
}