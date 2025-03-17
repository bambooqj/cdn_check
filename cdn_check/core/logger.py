"""
日志配置模块 - 统一管理日志配置
"""

import os
import logging
import json
from typing import Dict, Any, Optional

# 日志级别映射
LOG_LEVELS = {
    "debug": logging.DEBUG,
    "info": logging.INFO,
    "warning": logging.WARNING,
    "error": logging.ERROR,
    "critical": logging.CRITICAL
}

class LoggerManager:
    """日志管理器，负责统一配置日志"""
    
    _instance = None
    
    def __new__(cls):
        """实现单例模式"""
        if cls._instance is None:
            cls._instance = super(LoggerManager, cls).__new__(cls)
            cls._instance._config = None
            cls._instance._initialized = False
        return cls._instance
    
    def configure(self, config_path: Optional[str] = None, config_dict: Optional[Dict[str, Any]] = None) -> None:
        """
        配置日志
        
        Args:
            config_path: 配置文件路径
            config_dict: 配置字典
        """
        # 如果已经初始化过，先重置
        if self._initialized:
            self.reset()
        
        # 加载配置
        if config_dict:
            self._config = config_dict
        elif config_path and os.path.exists(config_path):
            with open(config_path, 'r', encoding='utf-8') as f:
                self._config = json.load(f)
        else:
            # 默认配置
            self._config = {
                "logging": {
                    "level": "info",
                    "file": "log/cdn_check.log",
                    "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
                }
            }
        
        # 确保日志目录存在
        log_file = self._config["logging"].get("file", "log/cdn_check.log")
        log_dir = os.path.dirname(log_file)
        os.makedirs(log_dir, exist_ok=True)
        
        # 配置根日志
        self._configure_logger()
        
        self._initialized = True
    
    def _configure_logger(self) -> None:
        """配置日志记录器"""
        log_config = self._config["logging"]
        
        # 获取日志级别
        level_name = log_config.get("level", "info").lower()
        level = LOG_LEVELS.get(level_name, logging.INFO)
        
        # 获取日志格式
        log_format = log_config.get("format", "%(asctime)s - %(name)s - %(levelname)s - %(message)s")
        formatter = logging.Formatter(log_format)
        
        # 配置根日志器
        root_logger = logging.getLogger()
        root_logger.setLevel(level)
        
        # 清除现有处理器
        for handler in root_logger.handlers[:]:
            root_logger.removeHandler(handler)
        
        # 添加控制台处理器
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        console_handler.setLevel(level)
        root_logger.addHandler(console_handler)
        
        # 添加文件处理器
        file_path = log_config.get("file", "log/cdn_check.log")
        if file_path:
            file_handler = logging.FileHandler(file_path)
            file_handler.setFormatter(formatter)
            file_handler.setLevel(level)
            root_logger.addHandler(file_handler)
        
        # 设置第三方库的日志级别
        for logger_name in ["urllib3", "requests", "asyncio"]:
            logging.getLogger(logger_name).setLevel(logging.WARNING)
    
    def get_logger(self, name: str) -> logging.Logger:
        """
        获取日志器
        
        Args:
            name: 日志器名称
            
        Returns:
            日志器实例
        """
        return logging.getLogger(name)
    
    def set_level(self, level: str) -> None:
        """
        设置全局日志级别
        
        Args:
            level: 日志级别
        """
        if level in LOG_LEVELS:
            logging.getLogger().setLevel(LOG_LEVELS[level])
    
    def reset(self) -> None:
        """重置日志配置"""
        root_logger = logging.getLogger()
        
        # 清除现有处理器
        for handler in root_logger.handlers[:]:
            root_logger.removeHandler(handler)
        
        # 重置配置
        self._config = None
        self._initialized = False

# 创建全局日志管理器实例
logger_manager = LoggerManager() 