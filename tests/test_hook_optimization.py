
import sys
import os
import unittest
import time
from unittest.mock import MagicMock

sys.path.insert(0, os.environ.get("PYTHONPATH", "."))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pyweixin.hook_types import PipeResponse, CommentResult, HookErrorCode, BatchCommentResult
from pyweixin.comment_dispatcher import HookCommentSender, CommentDispatcher, HookBridge

class MockBridgeForOptimization:
    def __init__(self, hook_installed=False, state_captured=False, capture_tid=0):
        self.hook_installed = hook_installed
        self.state_captured = state_captured
        self.capture_tid = capture_tid
        self.send_calls = 0
        self.parallel_calls = 0
        self.piggyback_calls = 0

    def status(self):
        return PipeResponse(
            ok=True,
            data={
                "hook_installed": self.hook_installed,
                "state_captured": self.state_captured,
                "capture_thread_id": self.capture_tid
            }
        )

    def send_comment(self, *args, **kwargs):
        self.send_calls += 1
        return PipeResponse(ok=True)

    def send_parallel_comments(self, *args, **kwargs):
        self.parallel_calls += 1
        return BatchCommentResult(succeeded=2, total=2, results=[CommentResult(success=True, method="hook"), CommentResult(success=True, method="hook")])

    def send_piggyback_comments(self, *args, **kwargs):
        self.piggyback_calls += 1
        return BatchCommentResult(succeeded=2, total=2)
    
    def query_sns_id(self, *args, **kwargs):
        return PipeResponse(ok=False)
        
    def get_latest_sns_id(self):
        return PipeResponse(ok=False)

class TestHookOptimization(unittest.TestCase):
    
    def test_is_hook_ready_false(self):
        bridge = MockBridgeForOptimization(hook_installed=True, state_captured=False)
        sender = HookCommentSender(bridge)
        self.assertFalse(sender.is_hook_ready())

    def test_is_hook_ready_true(self):
        bridge = MockBridgeForOptimization(hook_installed=True, state_captured=True)
        sender = HookCommentSender(bridge)
        self.assertTrue(sender.is_hook_ready())

    def test_send_comment_early_exit_when_not_ready(self):
        # Scenario: execution_mode="capture_thread", but capture_tid=0
        bridge = MockBridgeForOptimization(hook_installed=True, state_captured=False, capture_tid=0)
        sender = HookCommentSender(bridge, execution_mode="capture_thread")
        
        result = sender.send_comment("test", sns_id="123")
        
        self.assertFalse(result.success)
        self.assertEqual(result.error_code, HookErrorCode.SNS_ID_NOT_FOUND)
        self.assertIn("state not captured yet", result.error_message)
        self.assertEqual(bridge.send_calls, 0) # Should NOT call bridge.send_comment

    def test_send_comment_proceeds_when_ready(self):
        # Scenario: execution_mode="capture_thread", and capture_tid=1234
        bridge = MockBridgeForOptimization(hook_installed=True, state_captured=True, capture_tid=1234)
        sender = HookCommentSender(bridge, execution_mode="capture_thread")
        
        result = sender.send_comment("test", sns_id="123")
        
        self.assertTrue(result.success)
        self.assertEqual(bridge.send_calls, 1)

    def test_batch_auto_upgrade_piggyback_to_parallel(self):
        # Scenario: Batch mode "piggyback", but Hook is Ready (state captured) -> Upgrade to Parallel
        os.environ["PYWEIXIN_HOOK_BATCH_MODE"] = "piggyback"
        bridge = MockBridgeForOptimization(hook_installed=True, state_captured=True, capture_tid=1234)
        sender = HookCommentSender(bridge)
        dispatcher = CommentDispatcher(hook_sender=sender)
        
        # We pass 2 comments to ensure batch logic triggers
        dispatcher.post_batch_comments(["a", "b"], sns_id="123")
        
        # Should call parallel, NOT piggyback
        self.assertEqual(bridge.parallel_calls, 1)
        self.assertEqual(bridge.piggyback_calls, 0)

    def test_batch_no_upgrade_when_not_ready(self):
        # Scenario: Batch mode "piggyback", Hook NOT Ready -> Stay Piggyback (fallback flow)
        os.environ["PYWEIXIN_HOOK_BATCH_MODE"] = "piggyback"
        bridge = MockBridgeForOptimization(hook_installed=True, state_captured=False, capture_tid=0)
        sender = HookCommentSender(bridge)
        # We need a UI sender mock because piggyback falls back/bootstraps via UI
        ui_sender = MagicMock()
        ui_sender.send_comment.return_value = CommentResult(success=True, method="ui")
        
        dispatcher = CommentDispatcher(hook_sender=sender, ui_sender=ui_sender)
        
        # Just run it naturally. The thread will start, UI sender returns success, thread joins.
        dispatcher.post_batch_comments(["a", "b"], sns_id="123")
        
        # Should call piggyback, NOT parallel
        self.assertEqual(bridge.parallel_calls, 0)
        self.assertEqual(bridge.piggyback_calls, 1)

if __name__ == "__main__":
    unittest.main()
