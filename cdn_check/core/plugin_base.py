"""
插件基类 - 所有插件必须继承此类
"""

import logging
from typing import Dict, Any

logger = logging.getLogger(__name__)

class PluginBase:
    """插件基类，所有插件必须继承此类并实现相关方法"""
    
    # 插件类型（detector, analyzer, resolver 等）
    plugin_type = "base"
    
    # 插件名称（唯一标识）
    plugin_name = "base_plugin"
    
    # 插件描述
    plugin_description = "基础插件"
    
    # 插件版本
    plugin_version = "0.1.0"
    
    # 插件作者
    plugin_author = "CDN检测工具"
    
    def __init__(self):
        """初始化插件"""
        self._config = {}
        self._initialized = False
        logger.info(f"初始化插件: {self.plugin_name}")
    
    def initialize(self, config: Dict[str, Any]) -> bool:
        """
        初始化插件配置
        
        Args:
            config: 插件配置
            
        Returns:
            初始化是否成功
        """
        self._config = config or {}
        self._initialized = True
        logger.info(f"插件 {self.plugin_name} 初始化完成")
        return True
    
    def execute(self, *args, **kwargs) -> Any:
        """
        执行插件功能
        
        Args:
            *args, **kwargs: 参数
            
        Returns:
            执行结果
        """
        raise NotImplementedError("插件必须实现execute方法")
    
    def get_config(self, key: str, default: Any = None) -> Any:
        """
        获取配置项
        
        Args:
            key: 配置项键名
            default: 默认值
            
        Returns:
            配置项值
        """
        return self._config.get(key, default)
    
    def set_config(self, key: str, value: Any) -> None:
        """
        设置配置项
        
        Args:
            key: 配置项键名
            value: 配置项值
        """
        self._config[key] = value
        logger.debug(f"设置插件 {self.plugin_name} 配置项: {key}={value}")
    
    def update_config(self, config: Dict[str, Any]) -> None:
        """
        更新配置
        
        Args:
            config: 配置字典
        """
        self._config.update(config)
        logger.debug(f"更新插件 {self.plugin_name} 配置: {config}")
    
    def validate(self) -> bool:
        """
        验证插件配置是否有效
        
        Returns:
            配置是否有效
        """
        return True
    
    def shutdown(self) -> None:
        """关闭插件并释放资源"""
        self._initialized = False
        logger.info(f"插件 {self.plugin_name} 已关闭")
    
    def __str__(self) -> str:
        """返回插件字符串表示"""
        return f"{self.plugin_name} ({self.plugin_type}) - {self.plugin_description}"
    
    def get_info(self) -> Dict[str, Any]:
        """
        获取插件信息
        
        Returns:
            插件信息字典
        """
        return {
            'name': self.plugin_name,
            'type': self.plugin_type,
            'description': self.plugin_description,
            'version': self.plugin_version,
            'author': self.plugin_author,
            'initialized': self._initialized
        } 