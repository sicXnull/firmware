#pragma once
#include "configuration.h"
#include <ctime>
#include <iomanip>
#include <sstream>

// Redefine strptime in your source to avoid IRAM issue
inline char *strptime(const char *str, const char *format, struct tm *tm)
{
    if (sscanf(str, format, &tm->tm_year, &tm->tm_mon, &tm->tm_mday, &tm->tm_hour, &tm->tm_min, &tm->tm_sec) == 6) {
        tm->tm_year -= 1900; // Adjust year to be relative to 1900
        tm->tm_mon -= 1;     // Adjust month to be 0-based
        return (char *)(str + strlen(str));
    }
    return NULL;
}

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