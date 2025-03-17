"""
IP分析插件 - 用于分析IP地址
"""

from typing import Dict, Any, List, Optional

from cdn_check.core.plugin_base import PluginBase
from cdn_check.core.ip_analyzer import IPAnalyzer

class IPPlugin(PluginBase):
    """IP分析插件，用于分析IP地址"""
    
    plugin_type = "analyzer"
    plugin_name = "ip_analyzer"
    plugin_description = "IP分析插件，用于分析IP地址的地理位置和ASN信息"
    plugin_version = "0.1.0"
    plugin_author = "CDN检测工具"
    
    def __init__(self):
        super().__init__()
        self._analyzer = None
    
    def execute(self, target: str, **kwargs) -> Dict[str, Any]:
        """
        执行IP分析
        
        Args:
            target: 目标IP地址
            **kwargs: 其他参数
                - geo_db_path: GeoIP数据库路径
                - asn_db_path: ASN数据库路径
                - check_cdn: 是否检查是否为CDN IP
                - cdn_ip_ranges: CDN IP段列表
                
        Returns:
            IP分析结果
        """
        # 获取参数
        geo_db_path = kwargs.get('geo_db_path') or self.get_config('geo_db_path')
        asn_db_path = kwargs.get('asn_db_path') or self.get_config('asn_db_path')
        check_cdn = kwargs.get('check_cdn', True)
        cdn_ip_ranges = kwargs.get('cdn_ip_ranges') or self.get_config('cdn_ip_ranges', [])
        
        # 初始化分析器
        if not self._analyzer:
            self._analyzer = IPAnalyzer(geo_db_path, asn_db_path)
        
        result = {
            'plugin': self.plugin_name,
            'target': target,
            'success': True,
            'result': None,
            'is_cdn_ip': False
        }
        
        # 执行分析
        analysis_result = self._analyzer.analyze_ip(target)
        result['result'] = analysis_result
        
        # 检查是否为CDN IP
        if check_cdn and cdn_ip_ranges and analysis_result['is_valid']:
            result['is_cdn_ip'] = self._analyzer.is_cdn_ip(target, cdn_ip_ranges)
        
        return result
    
    def batch_execute(self, targets: List[str], **kwargs) -> List[Dict[str, Any]]:
        """
        批量执行IP分析
        
        Args:
            targets: 目标IP地址列表
            **kwargs: 其他参数
                
        Returns:
            IP分析结果列表
        """
        return [self.execute(target, **kwargs) for target in targets]
    
    def validate(self) -> bool:
        """
        验证插件配置是否有效
        
        Returns:
            配置是否有效
        """
        geo_db_path = self.get_config('geo_db_path')
        asn_db_path = self.get_config('asn_db_path')
        
        # 配置可以为空，将使用默认路径
        return True 