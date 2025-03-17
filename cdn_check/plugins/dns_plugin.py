"""
DNS解析插件 - 用于解析域名的IP地址和CNAME链
"""

from typing import Dict, Any, List, Optional

from cdn_check.core.plugin_base import PluginBase
from cdn_check.core.dns_resolver import DNSResolver
from cdn_check.core import get_logger

# 获取日志器
logger = get_logger(__name__)

class DNSPlugin(PluginBase):
    """DNS解析插件，用于解析域名的IP地址和CNAME链"""
    
    plugin_type = "resolver"
    plugin_name = "dns_resolver"
    plugin_description = "DNS解析插件，用于解析域名的IP地址和CNAME链"
    plugin_version = "0.1.0"
    plugin_author = "CDN检测工具"
    
    def __init__(self):
        super().__init__()
        self._resolver = None
    
    def execute(self, domain: str, **kwargs) -> Dict[str, Any]:
        """
        执行DNS解析
        
        Args:
            domain: 目标域名
            **kwargs: 其他参数
                - nameservers: 自定义DNS服务器列表
                - max_cname_depth: 最大CNAME解析深度
                - query_types: 查询类型列表 (默认 ['A', 'CNAME'])
                - cache_size: 缓存大小
                - cache_ttl: 缓存TTL（秒）
                
        Returns:
            DNS解析结果
        """
        # 获取参数
        nameservers = kwargs.get('nameservers') or self.get_config('nameservers')
        max_cname_depth = kwargs.get('max_cname_depth', 5)
        query_types = kwargs.get('query_types', ['A', 'CNAME'])
        cache_size = kwargs.get('cache_size', 1000)
        cache_ttl = kwargs.get('cache_ttl', 300)
        
        logger.info(f"执行DNS解析: {domain}")
        logger.debug(f"DNS解析参数: nameservers={nameservers}, max_cname_depth={max_cname_depth}")
        
        # 初始化解析器
        if not self._resolver:
            self._resolver = DNSResolver(cache_size=cache_size, cache_ttl=cache_ttl)
            
            # 设置自定义DNS服务器
            if nameservers:
                self._resolver.set_nameservers(nameservers)
                logger.info(f"设置DNS服务器: {nameservers}")
        
        result = {
            'plugin': self.plugin_name,
            'target': domain,
            'success': True,
            'result': None
        }
        
        # 执行解析
        try:
            dns_result = self._resolver.resolve(domain, max_cname_depth=max_cname_depth)
            result['result'] = dns_result
            logger.info(f"DNS解析成功: {domain}")
            logger.debug(f"DNS解析结果: {dns_result}")
        except Exception as e:
            result['success'] = False
            result['error'] = str(e)
            logger.error(f"DNS解析失败: {domain} - {str(e)}", exc_info=True)
        
        return result
    
    def validate(self) -> bool:
        """
        验证插件配置是否有效
        
        Returns:
            配置是否有效
        """
        nameservers = self.get_config('nameservers')
        if nameservers and not isinstance(nameservers, list):
            logger.error(f"DNS服务器配置无效，必须是列表: {nameservers}")
            return False
            
        cache_size = self.get_config('cache_size')
        if cache_size and not isinstance(cache_size, int):
            logger.error(f"缓存大小配置无效，必须是整数: {cache_size}")
            return False
            
        cache_ttl = self.get_config('cache_ttl')
        if cache_ttl and not isinstance(cache_ttl, int):
            logger.error(f"缓存TTL配置无效，必须是整数: {cache_ttl}")
            return False
        
        logger.info("DNS解析插件配置验证通过")
        return True
    
    def get_cache_stats(self) -> Dict[str, int]:
        """
        获取缓存统计信息
        
        Returns:
            缓存统计信息
        """
        if self._resolver:
            stats = self._resolver.get_cache_stats()
            logger.debug(f"DNS缓存统计: {stats}")
            return stats
        logger.warning("未初始化解析器，无法获取缓存统计")
        return {'size': 0, 'hits': 0, 'misses': 0}
    
    def clear_cache(self) -> None:
        """清除DNS解析缓存"""
        if self._resolver:
            self._resolver.clear_cache()
            logger.info("DNS缓存已清除")
        else:
            logger.warning("未初始化解析器，无法清除缓存")
    
    def shutdown(self) -> None:
        """关闭DNS解析插件"""
        self._resolver = None
        logger.info("DNS解析插件已关闭")
        super().shutdown()
