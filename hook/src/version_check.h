#pragma once

#include <string>

namespace pywechat {

/**
 * Detect the WeChat version from the loaded WeChatWin.dll file version info.
 *
 * Returns a version string like "4.0.1.23" or "unknown" on failure.
 */
std::string get_wechat_version();

}  // namespace pywechat
