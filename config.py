#!/usr/bin/env python3
# _*_ coding:utf-8 _*_
"""
微信读书自动刷时长脚本配置
适配青龙面板环境变量系统
"""
import os
import re
import sys

# 添加青龙面板路径，确保能导入notify模块
sys.path.append('/ql/scripts')
try:
    from notify import send
    HAS_NOTIFY = True
except ImportError:
    HAS_NOTIFY = False
    print("警告：未找到青龙notify模块，将使用原推送方式")

# ========== 基础配置 ==========
# 阅读次数（每次30秒，默认20次=10分钟）
READ_NUM = 20 #int(os.getenv('READ_NUM', '120'))

# 推送方法（留空则不推送，可选：pushplus, wxpusher, telegram等青龙支持的所有方式）
PUSH_METHOD = "wxpusher" #os.getenv('PUSH_METHOD', '')

# ========== 微信读书Cookie配置 ==========
WXREAD_CURL_BASH = os.getenv('WXREAD_CURL_BASH', '')

# ========== 青龙面板推送配置（通过环境变量设置）==========
# 以下为青龙面板支持的各种推送方式的环境变量名
# 用户只需在青龙面板的环境变量中配置对应值即可
# 
# 常用推送配置示例：
# PUSH_PLUS_TOKEN: pushplus的token
# TG_BOT_TOKEN: Telegram bot token
# TG_USER_ID: Telegram用户ID
# WXPUSHER_APP_TOKEN: wxpusher的appToken
# WXPUSHER_UIDS: wxpusher的用户ID（多个用;分隔）
# 更多配置请参考青龙面板的sendNotify.js/notify.py

# ========== 默认headers和cookies（当WXREAD_CURL_BASH为空时使用）==========
cookies = {
    'wr_skey': '',
    'pac_uid': '0_e63870bcecc18',
}

headers = {
    'accept': 'application/json, text/plain, */*',
    'accept-language': 'zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6,ko;q=0.5',
    'content-type': 'application/json',
    'origin': 'https://weread.qq.com',
    'referer': 'https://weread.qq.com/',
    'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0',
}

# 书籍ID列表（可随机选择）
book = [
    "36d322f07186022636daa5e", "6f932ec05dd9eb6f96f14b9", "43f3229071984b9343f04a4",
    "d7732ea0813ab7d58g0184b8", "3d03298058a9443d052d409", "4fc328a0729350754fc56d4",
    "a743220058a92aa746632c0", "140329d0716ce81f140468e", "1d9321c0718ff5e11d9afe8",
    "ff132750727dc0f6ff1f7b5", "e8532a40719c4eb7e851cbe", "9b13257072562b5c9b1c8d6"
]

# 章节ID列表（可随机选择）
chapter = [
    "ecc32f3013eccbc87e4b62e", "a87322c014a87ff679a21ea", "e4d32d5015e4da3b7fbb1fa",
    "16732dc0161679091c5aeb1", "8f132430178f14e45fce0f7", "c9f326d018c9f0f895fb5e4",
    "45c322601945c48cce2e120", "d3d322001ad3d9446802347", "65132ca01b6512bd43d90e3",
    "c20321001cc20ad4d76f5ae", "c51323901dc51ce410c121b", "aab325601eaab3238922e53",
    "9bf32f301f9bf31c7ff0a60", "c7432af0210c74d97b01b1c", "70e32fb021170efdf2eca12",
    "6f4322302126f4922f45dec"
]

# 默认阅读数据（阅读《三体》）
data = {
    "appId": "wb182564874603h266381671",
    "b": "ce032b305a9bc1ce0b0dd2a",  # 书籍ID
    "c": "7f632b502707f6ffaa6bf2e",  # 章节ID
    "ci": 27,                         # 章节索引
    "co": 389,                        # 字符偏移
    "sm": "19聚会《三体》网友的聚会地点是一处僻静",  # 片段
    "pr": 74,                         # 进度百分比
    "rt": 15,                         # 阅读时间（秒）
    "ts": 0,                          # 时间戳（会动态生成）
    "rn": 0,                          # 随机数（会动态生成）
    "sg": "",                         # 签名（会动态生成）
    "ct": 0,                          # 当前时间戳（会动态生成）
    "ps": "4ee326507a65a465g015fae",  # 上一节ID
    "pc": "aab32e207a65a466g010615",  # 上一章ID
    "s": ""                           # 哈希值（会动态生成）
}

# ========== 辅助函数 ==========
def parse_curl_command(curl_command):
    """
    从curl命令中提取headers和cookies
    支持格式：
    1. -H 'Cookie: xxx'
    2. -b 'xxx'
    """
    if not curl_command:
        return headers, cookies
    
    headers_temp = {}
    cookies_temp = {}
    
    # 提取headers
    header_matches = re.findall(r"-H\s+'([^:]+):\s*([^']+)'", curl_command)
    for key, value in header_matches:
        headers_temp[key.strip()] = value.strip()
    
    # 提取cookies（两种方式）
    cookie_string = ""
    
    # 方式1：从 -H 'Cookie:' 提取
    cookie_header = next((v for k, v in headers_temp.items() 
                         if k.lower() == 'cookie'), '')
    
    # 方式2：从 -b 参数提取
    cookie_b_match = re.search(r"-b\s+'([^']+)'", curl_command)
    if cookie_b_match:
        cookie_string = cookie_b_match.group(1)
    elif cookie_header:
        cookie_string = cookie_header
    
    # 解析cookie字符串
    if cookie_string:
        for cookie_item in cookie_string.split(';'):
            if '=' in cookie_item:
                key, value = cookie_item.strip().split('=', 1)
                cookies_temp[key] = value
    
    # 移除headers中的Cookie项（避免重复）
    final_headers = {k: v for k, v in headers_temp.items() 
                    if k.lower() != 'cookie'}
    
    # 更新默认headers
    final_headers.update(headers)
    
    # 更新默认cookies
    final_cookies = cookies.copy()
    final_cookies.update(cookies_temp)
    
    return final_headers, final_cookies

# 解析curl命令获取headers和cookies
if WXREAD_CURL_BASH:
    headers, cookies = parse_curl_command(WXREAD_CURL_BASH)
    print(f"✅ 已从环境变量解析Cookie，共{cookies}个cookie")
else:
    print("⚠️  未设置WXREAD_CURL_BASH环境变量，使用默认headers/cookies")

# ========== 配置验证 ==========
def validate_config():
    """验证配置是否完整"""
    errors = []
    
    if not WXREAD_CURL_BASH:
        errors.append("请设置WXREAD_CURL_BASH环境变量（抓包获取的curl命令）")
    
    if not cookies.get('wr_skey'):
        errors.append("Cookie中缺少wr_skey字段，请检查WXREAD_CURL_BASH格式")
    
    if not cookies.get('pac_uid'):
        errors.append("Cookie中缺少pac_uid字段")
    
    if errors:
        error_msg = "配置错误：\n" + "\n".join(f"  • {error}" for error in errors)
        print(error_msg)
        return False
    
    return True

if __name__ == "__main__":
    # 测试配置解析
    print("=" * 50)
    print("微信读书刷时长脚本配置检查")
    print("=" * 50)
    print(f"阅读次数: {READ_NUM}次（约{READ_NUM*0.5}分钟）")
    print(f"推送方式: {PUSH_METHOD if PUSH_METHOD else '无推送'}")
    print(f"Cookie解析: {'成功' if WXREAD_CURL_BASH else '使用默认值'}")
    print(f"Headers数量: {len(headers)}")
    print(f"Cookies数量: {len(cookies)}")
    print("=" * 50)
    
    if validate_config():
        print("✅ 配置检查通过")
    else:
        print("❌ 配置检查失败，请修复以上问题")