#!/usr/bin/env python3
"""
CDN检测工具命令行入口
"""

import sys
import os
import logging
from cdn_check.core.logger import logger_manager
from cdn_check.cli import cli

# 创建日志目录
os.makedirs('log', exist_ok=True)

# 初始化日志系统
config_path = 'config.json'
if os.path.exists(config_path):
    logger_manager.configure(config_path=config_path)
else:
    logger_manager.configure()
    logging.warning(f"配置文件 {config_path} 不存在，使用默认配置")

# 注意：不要在此处初始化插件，避免重复加载
# 插件初始化会在CDNCheckApp实例化时进行

if __name__ == '__main__':
    try:
        cli()
    except KeyboardInterrupt:
        print("\n程序已被用户中断")
        sys.exit(1)
    except Exception as e:
        print(f"程序执行过程中出现错误: {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
