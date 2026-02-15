#!/usr/bin/env python3
# _*_ coding:utf-8 _*_
"""
微信读书自动刷时长脚本主程序
适配青龙面板通知系统
"""
import json
import time
import random
import hashlib
import urllib.parse
import logging
import sys
import requests

# 添加青龙面板路径
sys.path.append('/ql/scripts')
try:
    from notify import send as ql_send
    HAS_QL_NOTIFY = True
except ImportError:
    HAS_QL_NOTIFY = False

# 导入配置文件
from config import (
    data, headers, cookies, READ_NUM, PUSH_METHOD,
    book, chapter, validate_config
)

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger('wxread')

# 加密盐和URL
KEY = "3c5c8717f3daf09iop3423zafeqoi"
COOKIE_DATA = {"rq": "%2Fweb%2Fbook%2Fread"}
READ_URL = "https://weread.qq.com/web/book/read"
RENEW_URL = "https://weread.qq.com/web/login/renewal"
FIX_SYNCKEY_URL = "https://weread.qq.com/web/book/chapterInfos"

def encode_data(data_dict):
    """对数据进行URL编码排序"""
    sorted_items = sorted(data_dict.items(), key=lambda x: x[0])
    encoded_items = []
    for key, value in sorted_items:
        encoded_value = urllib.parse.quote(str(value), safe='')
        encoded_items.append(f"{key}={encoded_value}")
    return '&'.join(encoded_items)

def calculate_hash(input_string):
    """计算请求签名哈希值"""
    hash_value1 = 0x15051505
    hash_value2 = hash_value1
    length = len(input_string)
    index = length - 1
    
    while index > 0:
        hash_value1 = 0x7fffffff & (hash_value1 ^ ord(input_string[index]) << (length - index) % 30)
        hash_value2 = 0x7fffffff & (hash_value2 ^ ord(input_string[index - 1]) << index % 30)
        index -= 2
    
    return hex(hash_value1 + hash_value2)[2:].lower()

def refresh_cookie():
    """刷新微信读书Cookie"""
    logger.info("正在刷新Cookie...")
    try:
        response = requests.post(
            RENEW_URL,
            headers=headers,
            cookies=cookies,
            data=json.dumps(COOKIE_DATA, separators=(',', ':')),
            timeout=10
        )
        
        # 从响应头中提取新的wr_skey
        set_cookie = response.headers.get('Set-Cookie', '')
        for cookie_item in set_cookie.split(';'):
            if 'wr_skey' in cookie_item:
                new_skey = cookie_item.split('=')[1].split(';')[0][:8]
                cookies['wr_skey'] = new_skey
                logger.info(f"✅ Cookie刷新成功，新密钥：{new_skey}")
                return True
        
        logger.error("❌ 未找到新的wr_skey")
        return False
        
    except Exception as e:
        logger.error(f"❌ Cookie刷新失败: {e}")
        return False

def fix_synckey():
    """修复缺少synckey的情况"""
    try:
        response = requests.post(
            FIX_SYNCKEY_URL,
            headers=headers,
            cookies=cookies,
            data=json.dumps({"bookIds": ["3300060341"]}, separators=(',', ':')),
            timeout=10
        )
        if response.status_code == 200:
            logger.info("✅ synckey修复请求发送成功")
            return True
        else:
            logger.warning(f"⚠️  synckey修复失败: HTTP {response.status_code}")
            return False
    except Exception as e:
        logger.error(f"❌ synckey修复异常: {e}")
        return False

def send_notification(title, content):
    """发送通知（使用青龙面板的notify模块）"""
    if not PUSH_METHOD:
        logger.info("未配置推送方式，跳过通知")
        return False
    
    try:
        if HAS_QL_NOTIFY:
            # 使用青龙面板的send函数
            logger.info(f"使用青龙面板通知系统发送: {title}")
            ql_send(title, content)
            return True
        else:
            logger.warning("未找到青龙notify模块，无法发送通知")
            return False
    except Exception as e:
        logger.error(f"❌ 通知发送失败: {e}")
        return False

def simulate_reading():
    """模拟阅读主函数"""
    logger.info("=" * 50)
    logger.info("微信读书自动刷时长脚本启动")
    logger.info(f"目标阅读次数: {READ_NUM}次（约{READ_NUM * 0.5}分钟）")
    logger.info("=" * 50)
    
    # 验证配置
    if not validate_config():
        error_msg = "配置验证失败，请检查WXREAD_CURL_BASH环境变量"
        send_notification("微信读书刷时长失败", error_msg)
        return False
    
    # 初始Cookie刷新
    if not refresh_cookie():
        error_msg = "初始Cookie刷新失败，请检查网络或Cookie有效性"
        send_notification("微信读书刷时长失败", error_msg)
        return False
    
    index = 1
    last_time = int(time.time()) - 30
    success_count = 0
    failed_count = 0
    
    while index <= READ_NUM:
        try:
            # 准备请求数据
            current_data = data.copy()
            current_data.pop('s', None)  # 移除旧的签名
            
            # 随机选择书籍和章节
            current_data['b'] = random.choice(book)
            current_data['c'] = random.choice(chapter)
            
            # 设置时间参数
            current_time = int(time.time())
            current_data['ct'] = current_time
            current_data['rt'] = current_time - last_time
            current_data['ts'] = current_time * 1000 + random.randint(0, 1000)
            current_data['rn'] = random.randint(0, 1000)
            
            # 计算签名
            signature_base = f"{current_data['ts']}{current_data['rn']}{KEY}"
            current_data['sg'] = hashlib.sha256(signature_base.encode()).hexdigest()
            current_data['s'] = calculate_hash(encode_data(current_data))
            
            logger.info(f"📖 第 {index}/{READ_NUM} 次阅读尝试")
            logger.debug(f"请求数据: {json.dumps(current_data, ensure_ascii=False)}")
            
            # 发送阅读请求
            response = requests.post(
                READ_URL,
                headers=headers,
                cookies=cookies,
                data=json.dumps(current_data, separators=(',', ':')),
                timeout=15
            )
            
            response_data = response.json()
            logger.debug(f"响应数据: {json.dumps(response_data, ensure_ascii=False)}")
            
            if 'succ' in response_data:
                if 'synckey' in response_data:
                    # 阅读成功
                    last_time = current_time
                    success_count += 1
                    progress = (index / READ_NUM) * 100
                    logger.info(f"✅ 阅读成功 ({success_count}次) - 进度: {progress:.1f}%")
                    
                    index += 1
                    if index <= READ_NUM:
                        # 等待30秒进行下一次阅读
                        time.sleep(30)
                else:
                    # 缺少synckey，尝试修复
                    logger.warning("⚠️  响应中缺少synckey，尝试修复...")
                    if fix_synckey():
                        # 修复后重试本次阅读
                        continue
                    else:
                        failed_count += 1
                        logger.error("❌ synckey修复失败")
                        if failed_count >= 3:
                            error_msg = "连续3次synckey修复失败，停止运行"
                            send_notification("微信读书刷时长异常", error_msg)
                            return False
            else:
                # Cookie可能过期，尝试刷新
                logger.warning("❌ 阅读失败，可能Cookie已过期，尝试刷新...")
                if refresh_cookie():
                    # Cookie刷新成功，重试本次阅读
                    logger.info("🔄 Cookie刷新成功，重试本次阅读")
                    continue
                else:
                    failed_count += 1
                    logger.error("❌ Cookie刷新失败")
                    if failed_count >= 3:
                        error_msg = "连续3次Cookie刷新失败，停止运行"
                        send_notification("微信读书刷时长失败", error_msg)
                        return False
                        
        except requests.exceptions.RequestException as e:
            logger.error(f"❌ 网络请求异常: {e}")
            failed_count += 1
            if failed_count >= 3:
                error_msg = f"连续3次网络异常: {e}"
                send_notification("微信读书刷时长网络异常", error_msg)
                return False
            time.sleep(5)  # 网络异常稍作等待
            continue
            
        except Exception as e:
            logger.error(f"❌ 未知错误: {e}")
            failed_count += 1
            if failed_count >= 3:
                error_msg = f"连续3次未知错误: {e}"
                send_notification("微信读书刷时长异常", error_msg)
                return False
            time.sleep(5)
            continue
    
    # 阅读完成
    total_minutes = success_count * 0.5
    success_msg = (
        f"🎉 微信读书自动刷时长完成！\n\n"
        f"📊 统计信息：\n"
        f"• 成功阅读次数: {success_count}/{READ_NUM}\n"
        f"• 失败次数: {failed_count}\n"
        f"• 累计时长: {total_minutes:.1f}分钟\n"
        f"• 完成时间: {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n"
        f"✅ 任务执行成功！"
    )
    
    logger.info("=" * 50)
    logger.info(f"脚本执行完成")
    logger.info(f"成功: {success_count}次, 失败: {failed_count}次")
    logger.info(f"累计阅读时长: {total_minutes:.1f}分钟")
    logger.info("=" * 50)
    
    # 发送完成通知
    if PUSH_METHOD:
        send_notification("微信读书刷时长完成", success_msg)
    
    return True

def main():
    """主函数"""
    try:
        success = simulate_reading()
        if success:
            logger.info("✅ 脚本执行成功")
            return 0
        else:
            logger.error("❌ 脚本执行失败")
            return 1
    except KeyboardInterrupt:
        logger.info("⏹️  用户中断执行")
        send_notification("微信读书刷时长中断", "用户手动中断了脚本执行")
        return 130
    except Exception as e:
        logger.error(f"❌ 脚本执行异常: {e}")
        send_notification("微信读书刷时长异常", f"脚本执行异常: {str(e)}")
        return 1

if __name__ == "__main__":
    exit_code = main()
    sys.exit(exit_code)