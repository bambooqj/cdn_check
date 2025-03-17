"""
插件管理器 - 负责加载、管理和执行插件
"""

import importlib
import inspect
import logging
import os
import pkgutil
import sys
from typing import Dict, List, Type, Optional, Any

from cdn_check.core.plugin_base import PluginBase

logger = logging.getLogger(__name__)

class PluginManager:
    """插件管理器类，负责插件的加载、注册和执行"""
    
    _instance = None
    
    def __new__(cls):
        """实现单例模式"""
        if cls._instance is None:
            cls._instance = super(PluginManager, cls).__new__(cls)
            cls._instance._plugins = {}
            cls._instance._plugin_instances = {}
        return cls._instance
    
    def __init__(self):
        """初始化插件管理器"""
        # 单例模式下不需要重复初始化
        pass
        
    def discover_plugins(self, package_name: str) -> None:
        """
        从指定包中发现所有插件
        
        Args:
            package_name: 包含插件的包名
        """
        logger.info(f"开始发现插件: {package_name}")
        try:
            package = importlib.import_module(package_name)
            logger.info(f"成功导入包: {package_name}")
            
            # 获取包的路径
            package_path = getattr(package, '__path__', [])
            
            # 使用pkgutil发现所有模块
            for _, name, is_pkg in pkgutil.iter_modules(package_path, package.__name__ + '.'):
                if is_pkg:
                    continue  # 跳过子包
                    
                try:
                    # 导入模块
                    module = importlib.import_module(name)
                    logger.info(f"导入模块: {name}")
                    
                    # 查找模块中的插件类
                    for item_name, item in inspect.getmembers(module, inspect.isclass):
                        # 检查是否是插件基类的子类，但不是基类本身
                        if (issubclass(item, PluginBase) and 
                            item != PluginBase and 
                            hasattr(item, 'plugin_type') and
                            hasattr(item, 'plugin_name')):
                            logger.info(f"发现插件类: {item_name} in {name}")
                            self.register_plugin(item)
                except ImportError as e:
                    logger.warning(f"导入模块失败: {name} - {str(e)}")
                except Exception as e:
                    logger.error(f"处理模块时出错: {name} - {str(e)}")
        except Exception as e:
            logger.error(f"发现插件过程中出错: {str(e)}", exc_info=True)
        
        logger.info(f"插件发现完成，已注册插件: {list(self._plugins.keys())}")
    
    def register_plugin(self, plugin_class: Type[PluginBase]) -> None:
        """
        注册插件类
        
        Args:
            plugin_class: 插件类
        """
        try:
            plugin_name = plugin_class.plugin_name
            if plugin_name in self._plugins:
                logger.warning(f"插件 {plugin_name} 已存在，将被覆盖")
            
            self._plugins[plugin_name] = plugin_class
            logger.info(f"已注册插件: {plugin_name} ({plugin_class.plugin_type})")
        except Exception as e:
            logger.error(f"注册插件时出错: {str(e)}")
    
    def get_plugin(self, plugin_name: str) -> Optional[PluginBase]:
        """
        获取插件实例
        
        Args:
            plugin_name: 插件名称
            
        Returns:
            插件实例，如果不存在则返回None
        """
        # 如果实例已存在，直接返回
        if plugin_name in self._plugin_instances:
            return self._plugin_instances[plugin_name]
            
        # 如果插件类已注册但实例不存在，创建实例
        if plugin_name in self._plugins:
            try:
                logger.info(f"实例化插件: {plugin_name}")
                self._plugin_instances[plugin_name] = self._plugins[plugin_name]()
                return self._plugin_instances[plugin_name]
            except Exception as e:
                logger.error(f"实例化插件 {plugin_name} 时出错: {str(e)}")
                return None
        else:
            logger.warning(f"插件 {plugin_name} 不存在")
            return None
    
    def get_plugins_by_type(self, plugin_type: str) -> List[str]:
        """
        获取指定类型的所有插件名称
        
        Args:
            plugin_type: 插件类型
            
        Returns:
            插件名称列表
        """
        return [name for name, plugin in self._plugins.items() 
                if plugin.plugin_type == plugin_type]
    
    def execute_plugin(self, plugin_name: str, *args, **kwargs) -> Any:
        """
        执行指定插件
        
        Args:
            plugin_name: 插件名称
            *args, **kwargs: 传递给插件的参数
            
        Returns:
            插件执行结果
        """
        plugin = self.get_plugin(plugin_name)
        if plugin:
            try:
                logger.info(f"执行插件: {plugin_name}")
                return plugin.execute(*args, **kwargs)
            except Exception as e:
                logger.error(f"执行插件 {plugin_name} 时出错: {str(e)}")
                return None
        return None
    
    def list_plugins(self) -> Dict[str, List[str]]:
        """
        列出所有已注册的插件
        
        Returns:
            按类型分组的插件名称字典
        """
        result = {}
        for name, plugin_class in self._plugins.items():
            plugin_type = plugin_class.plugin_type
            if plugin_type not in result:
                result[plugin_type] = []
            result[plugin_type].append(name)
        
        logger.info(f"当前已注册插件: {result}")
        return result

# 创建全局插件管理器实例
plugin_manager = PluginManager() 