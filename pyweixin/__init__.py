
'''
pyweixin
========


pywechat下的微信4.0版本的自动化工具
    可前往 'https://github.com/Hello-Mr-Crab/pywechat' 查看详情


Modules
-------
    - `WeChatTools`: 该模块中封装了Tools与Navigator两个静态类,主要用来辅助WeChatAuto实现其他自动化功能
    - `WeChatAuto`: pyweixin的主要模块,其内部包含消息,通讯录,文件,好友设置,朋友圈,自动回复,消息监控,微信设置这几个功能对应的静态类
    - `WinSettings`: 一些修改windows系统设置的方法
    - `Uielements`: 微信主界面内UI的封装
    - `Warnings`: 一些可能触发的警告
 
Examples:
--------

使用pyweixin时,你可以:

    >>> from pyweixin.WeChatAuto import Monitor
    >>> from pyweixin.WeChatTools import Navigator 
    >>> dialog_window=Navigator.open_seperate_dialog_window(friend='好友')
    >>> newMessages=Monitor.listen_on_chat(dialog_window,'1min')
    >>> print(newMessages)

或者:

    >>> from pyweixin import Monitor,Navigator
    >>> dialog_window=Navigator.open_seperate_dialog_window(friend='好友')
    >>> newMessages=Monitor.listen_on_chat(dialog_window,'1min')
    >>> print(newMessages)

支持版本:
    - `操作系统`: window10,windows11
    - `Python版本`: 3.8+(需支持TypeHint)

    
Have fun in WechatAutomation (＾＿－)
====
'''
from pyweixin.WeChatAuto import Messages,Contacts,Files,FriendSettings,Moments,AutoReply,Monitor,Settings,Collections
from pyweixin.WeChatTools import Tools,Navigator
from pyweixin.WinSettings import SystemSettings
from pyweixin.Config import GlobalConfig
# viper 扩展
from pyweixin.moments_ext import (
    fetch_and_comment_friend_moment,
    fetch_and_comment_from_moments_feed,
    dump_friend_moments,
    like_posts,
    like_friend_posts,
    comment_flow,
)
from pyweixin.rush_engine import run_rush_loop,load_rush_config,resolve_answer,parse_answer_from_templates
from pyweixin.rush_types import RushConfig,QuestionTemplate,AnswerResult
from pyweixin.rush_ai import ArkResponsesProvider,SiliconFlowOpenAIProvider,NullAIProvider,NullOCRProvider,PaddleOCRProvider
from pyweixin.rush_callback_multi import (
    OCRCommentSource,
    AICommentSource,
    CannedCommentSource,
    OCRRetryCommentSource,
    DynamicCommentSource,
    create_multi_source_streaming_callback,
)
from pyweixin.hook_types import HookErrorCode,CommentResult,CommentSender,HookCommentCommand,StatusCommand,BatchCommentCommand,BatchCommentResult,GetLatestSnsIdCommand,ReadMemoryCommand,ParallelCommentCommand,TlsDiagCommand
from pyweixin.hook_bridge import HookBridge
from pyweixin.comment_dispatcher import CommentDispatcher,CircuitBreakerState
from pyweixin.hook_injector import find_wechat_pid,inject_dll,eject_dll,is_dll_loaded
#Author:Hello-Mr-Crab
#Contributor:Viper,Chanpoe,mrhan1993,nmhjklnm,clen1,guanjt3
