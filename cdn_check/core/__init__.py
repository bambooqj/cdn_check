"""
CDN检测工具核心组件包
"""

from cdn_check.core.logger import logger_manager

def get_logger(name):
    """
    获取日志器
    
    Args:
        name: 日志器名称（通常是模块的__name__）
        
    Returns:
        日志器实例
    """
    return logger_manager.get_logger(name) 