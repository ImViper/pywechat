#pragma once

#include <string>

namespace pywechat {

/**
 * Result of a comment attempt via direct function call.
 */
struct CommentResult {
    bool success = false;
    int error_code = 0;
    std::string error_message;
};

/**
 * Send a comment on a Moments post by calling the WeChat internal function.
 *
 * **PLACEHOLDER** -- the actual function signature and call convention need
 * to be filled in after reverse engineering the WeChat binary.
 *
 * @param sns_id    The internal SNS object ID of the post.
 * @param content   Comment text (UTF-8).
 * @param reply_to  wxid to reply to (empty for top-level comment).
 * @return          CommentResult with success/failure info.
 */
CommentResult sns_do_comment(const std::string& sns_id,
                              const std::string& content,
                              const std::string& reply_to);

}  // namespace pywechat
