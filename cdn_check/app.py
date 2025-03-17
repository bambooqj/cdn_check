"""
CDN检测应用程序 - 核心应用逻辑
"""

import json
import logging
import os
import asyncio
from typing import Dict, List, Any, Optional, Tuple
from urllib.parse import urlparse
import time
import concurrent.futures
import ipaddress
import socket

from cdn_check.core.plugin_manager import plugin_manager
from cdn_check.core.db_manager import DBManager

logger = logging.getLogger(__name__)

class CDNCheckApp:
    """CDN检测应用程序类，提供检测CDN的核心功能"""
    
    def __init__(self, config_file: Optional[str] = None):
        """
        初始化CDN检测应用
        
        Args:
            config_file: 配置文件路径，如果为None则使用默认配置
        """
        # 初始化检测结果存储
        self.last_detection_result = None
        self.last_detection_domain = None
        
        # 加载配置
        if config_file is None:
            script_dir = os.path.dirname(os.path.abspath(__file__))
            root_dir = os.path.dirname(script_dir)
            config_file = os.path.join(root_dir, 'config.json')
        
        self._config = self._load_config(config_file)
        self._initialize_plugins()
        
        # 初始化数据库
        self._db = DBManager()
    
    def _load_config(self, config_file: Optional[str]) -> Dict[str, Any]:
        """
        加载配置文件
        
        Args:
            config_file: 配置文件路径
            
        Returns:
            配置字典
        """
        # 默认配置
        default_config = {
            "plugins": {
                "dns_resolver": {
                    "enabled": True,
                    "nameservers": ["8.8.8.8", "8.8.4.4"],
                    "cache_size": 1000,
                    "cache_ttl": 300
                },
                "http_requester": {
                    "enabled": True,
                    "timeout": 10,
                    "verify_ssl": True
                },
                "cert_analyzer": {
                    "enabled": True,
                    "port": 443,
                    "timeout": 10
                },
                "ip_analyzer": {
                    "enabled": True,
                    "geo_db_path": "data/geoip/GeoLite2-City.mmdb",
                    "asn_db_path": "data/geoip/GeoLite2-ASN.mmdb"
                },
                "cdn_detector": {
                    "enabled": True,
                    "rules_file": "data/cdn/rules.json"
                }
            },
            "system": {
                "concurrency": 10,
                "timeout": 30,
                "retry": 3,
                "retry_delay": 2,
                "log_level": "INFO",
                "output_dir": "reports"
            }
        }
        
        config = default_config
        
        if config_file:
            try:
                if os.path.exists(config_file):
                    with open(config_file, 'r', encoding='utf-8') as f:
                        user_config = json.load(f)
                        
                    # 递归合并配置
                    config = self._merge_config(default_config, user_config)
                    logger.info(f"已从 {config_file} 加载配置")
                else:
                    logger.warning(f"配置文件 {config_file} 不存在，使用默认配置")
            except Exception as e:
                logger.error(f"加载配置文件时出错: {str(e)}")
        else:
            # 尝试加载默认配置文件
            default_paths = ['config.json', 'conf/config.json', os.path.expanduser('~/.cdn_check/config.json')]
            
            for path in default_paths:
                if os.path.exists(path):
                    try:
                        with open(path, 'r', encoding='utf-8') as f:
                            user_config = json.load(f)
                            
                        # 递归合并配置
                        config = self._merge_config(default_config, user_config)
                        logger.info(f"已从 {path} 加载配置")
                        break
                    except Exception as e:
                        logger.error(f"加载默认配置文件 {path} 时出错: {str(e)}")
        
        return config
    
    def _merge_config(self, default_config: Dict[str, Any], user_config: Dict[str, Any]) -> Dict[str, Any]:
        """
        递归合并配置字典
        
        Args:
            default_config: 默认配置
            user_config: 用户配置
            
        Returns:
            合并后的配置
        """
        result = default_config.copy()
        
        for key, value in user_config.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = self._merge_config(result[key], value)
            else:
                result[key] = value
                
        return result
    
    def _initialize_plugins(self) -> None:
        """初始化插件"""
        logger.info("开始初始化插件")
        
        # 加载插件
        # 检查插件是否已经加载，避免重复调用discover_plugins
        if not plugin_manager.list_plugins():
            plugin_manager.discover_plugins("cdn_check.plugins")
        
        # 初始化启用的插件
        for plugin_type, plugins in plugin_manager.list_plugins().items():
            for plugin_name in plugins:
                plugin_config = self._config.get("plugins", {}).get(plugin_name, {})
                
                if plugin_config.get("enabled", True):
                    plugin = plugin_manager.get_plugin(plugin_name)
                    if plugin:
                        plugin.initialize(plugin_config)
                        logger.info(f"已初始化插件: {plugin_name} ({plugin_type})")
                else:
                    logger.info(f"插件 {plugin_name} 已禁用")
    
    async def check_target(self, target: str) -> Dict[str, Any]:
        """
        检测目标是否使用CDN
        
        Args:
            target: 目标域名或IP
            
        Returns:
            检测结果
        """
        logger.info(f"开始检测目标: {target}")
        
        # 预处理目标
        if not target.startswith(('http://', 'https://')):
            if ':' in target:  # 可能是IP:端口
                parts = target.split(':')
                if len(parts) == 2 and parts[1].isdigit():
                    hostname = parts[0]
                else:
                    hostname = target
            else:
                hostname = target
        else:
            from urllib.parse import urlparse
            hostname = urlparse(target).netloc
            if ':' in hostname:
                hostname = hostname.split(':')[0]
        
        try:
            # 并行执行所有插件
            dns_result = await self._run_plugin('dns_resolver', {'domain': hostname})
            http_result = await self._run_plugin('http_requester', {'url': target})
            
            # 预处理IP和CNAME数据
            ip_list = []
            if dns_result and 'a_records' in dns_result:
                ip_list = dns_result['a_records']
            
            cname_list = []
            if dns_result and 'cname_chain' in dns_result:
                if isinstance(dns_result['cname_chain'], list):
                    cname_list = dns_result['cname_chain']
                elif dns_result['cname_chain']:
                    cname_list = [dns_result['cname_chain']]
            
            # 获取证书信息
            cert_result = await self._run_plugin('cert_analyzer', {'domain': hostname})
            
            # 获取IP地理信息
            ip_info = {}
            for ip in ip_list:
                ip_result = await self._run_plugin('ip_analyzer', {'ip': ip})
                if ip_result:
                    ip_info[ip] = ip_result
            
            # 准备CDN检测数据
            cdn_data = {
                'domain': hostname,
                'ips': ip_list,
                'cname_chain': cname_list,
                'http_headers': http_result.get('headers', {}) if http_result else {},
                'cert': cert_result,
                'ip_info': ip_info
            }
            
            # 执行CDN检测
            cdn_result = await self._run_plugin('cdn_detector', cdn_data)
            
            # 整合所有结果
            result = {
                'success': True,
                'target': target,
                'is_cdn': cdn_result.get('is_cdn', False) if cdn_result else False,
                'cdn_provider': cdn_result.get('cdn_provider') if cdn_result else None,
                'confidence': cdn_result.get('confidence', 0) if cdn_result else 0,
                'indicators': cdn_result.get('indicators', []) if cdn_result else [],
                'details': {
                    'dns': dns_result or {},
                    'http': http_result or {},
                    'cert': cert_result or {},
                    'ip': ip_info or {}
                }
            }
            
            # 保存结果到数据库
            self._save_result_to_db(target, result)
            
            # 保存结果到CDN插件的last_result
            cdn_plugin = plugin_manager.get_plugin('cdn_detector')
            if cdn_plugin:
                cdn_plugin.last_result = {
                    'is_cdn': result['is_cdn'],
                    'cdn_provider': result['cdn_provider'],
                    'target': target,
                    'indicators': result.get('indicators', [])
                }
            
            logger.info(f"检测完成: {target}, 结果: {result['is_cdn']}")
            return result
            
        except Exception as e:
            logger.error(f"检测失败: {str(e)}", exc_info=True)
            return {
                'success': False,
                'target': target,
                'error': str(e)
            }
    
    async def _run_plugin(self, plugin_name: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        运行指定的插件
        
        Args:
            plugin_name: 插件名称
            data: 插件输入数据
            
        Returns:
            插件执行结果
        """
        plugin = plugin_manager.get_plugin(plugin_name)
        if not plugin:
            logger.error(f"插件不存在: {plugin_name}")
            return {}
            
        try:
            # 从字典中提取需要的值而不是传递整个字典
            if plugin_name == 'dns_resolver' and 'domain' in data:
                result = plugin.execute(data['domain'])
            elif plugin_name == 'http_requester' and 'url' in data:
                result = plugin.execute(data['url'])
            elif plugin_name == 'cert_analyzer' and 'domain' in data:
                result = plugin.execute(data['domain'])
            elif plugin_name == 'ip_analyzer' and 'ip' in data:
                result = plugin.execute(data['ip'])
            else:
                # cdn_detector等其他插件可能需要整个字典数据
                result = plugin.execute(data)
            
            if isinstance(result, dict) and result.get('success', False):
                return result.get('result', {})
            return {}
        except Exception as e:
            logger.error(f"运行插件 {plugin_name} 时出错: {str(e)}", exc_info=True)
            return {}
    
    def _save_result_to_db(self, target: str, result: Dict[str, Any]) -> None:
        """
        保存检测结果到数据库
        
        Args:
            target: 检测目标
            result: 检测结果
        """
        try:
            session_id = self._db.save_detection_result(target, result)
            if session_id > 0:
                logger.info(f"已保存检测结果到数据库，会话ID: {session_id}")
            else:
                logger.warning("保存检测结果到数据库失败")
        except Exception as e:
            logger.error(f"保存检测结果到数据库时出错: {str(e)}", exc_info=True)
            
    def provide_feedback(self, target: str, is_correct: bool, actual_provider: Optional[str] = None) -> bool:
        """
        提供检测结果的反馈
        
        Args:
            target: 检测目标
            is_correct: 检测结果是否正确
            actual_provider: 实际的CDN提供商（如果已知）
            
        Returns:
            是否成功提供反馈
        """
        try:
            # 获取目标的最新检测会话
            session = self._db.get_latest_session_for_target(target)
            if not session:
                logger.warning(f"未找到目标 {target} 的检测会话")
                return False
            
            # 保存反馈
            success = self._db.save_feedback(session['id'], is_correct, actual_provider)
            return success
        except Exception as e:
            logger.error(f"提供反馈时出错: {str(e)}", exc_info=True)
            return False
    
    async def check_targets(self, targets: List[str]) -> List[Dict[str, Any]]:
        """
        批量检测多个目标
        
        Args:
            targets: 目标列表
            
        Returns:
            检测结果列表
        """
        logger.info(f"开始批量检测 {len(targets)} 个目标")
        
        concurrency = self._config.get("system", {}).get("concurrency", 10)
        logger.info(f"并发数: {concurrency}")
        
        results = []
        
        # 创建任务
        tasks = [self.check_target(target) for target in targets]
        
        # 并发执行
        for i in range(0, len(tasks), concurrency):
            batch = tasks[i:i+concurrency]
            batch_results = await asyncio.gather(*batch, return_exceptions=True)
            
            for j, result in enumerate(batch_results):
                if isinstance(result, Exception):
                    logger.error(f"检测目标 {targets[i+j]} 时出错: {str(result)}")
                    results.append({
                        "target": targets[i+j],
                        "success": False,
                        "error": str(result)
                    })
                else:
                    results.append(result)
            
            logger.info(f"已完成 {min(i+concurrency, len(tasks))}/{len(tasks)} 个目标的检测")
        
        return results
    
    def check_targets_sync(self, targets: List[str]) -> List[Dict[str, Any]]:
        """
        同步方式批量检测多个目标
        
        Args:
            targets: 目标列表
            
        Returns:
            检测结果列表
        """
        return asyncio.run(self.check_targets(targets))
    
    def get_plugin_info(self) -> Dict[str, List[Dict[str, Any]]]:
        """
        获取插件信息
        
        Returns:
            插件信息
        """
        result = {}
        
        for plugin_type, plugins in plugin_manager.list_plugins().items():
            if plugin_type not in result:
                result[plugin_type] = []
                
            for plugin_name in plugins:
                plugin = plugin_manager.get_plugin(plugin_name)
                if plugin:
                    plugin_info = plugin.get_info()
                    plugin_info["enabled"] = self._config.get("plugins", {}).get(plugin_name, {}).get("enabled", True)
                    result[plugin_type].append(plugin_info)
        
        return result
    
    def shutdown(self) -> None:
        """关闭应用程序并释放资源"""
        logger.info("关闭应用程序")
        
        # 关闭所有插件
        for plugin_type, plugins in plugin_manager.list_plugins().items():
            for plugin_name in plugins:
                plugin = plugin_manager.get_plugin(plugin_name)
                if plugin:
                    plugin.shutdown()
                    logger.info(f"已关闭插件: {plugin_name}")
