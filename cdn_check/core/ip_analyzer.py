"""
IP分析模块 - 用于分析IP地址的地理位置和ASN信息
"""

import os
import logging
import ipaddress
from typing import Dict, Any, Optional, List, Tuple, Union

logger = logging.getLogger(__name__)

# 尝试导入第三方库
try:
    import geoip2.database
    import geoip2.errors
    GEOIP_AVAILABLE = True
except ImportError:
    logger.warning("geoip2库未安装，地理位置分析功能将受限")
    GEOIP_AVAILABLE = False

class IPAnalyzer:
    """IP地址分析器，提供地理位置和ASN信息查询"""
    
    def __init__(self, geo_db_path: Optional[str] = None, asn_db_path: Optional[str] = None):
        """
        初始化IP分析器
        
        Args:
            geo_db_path: GeoIP2城市数据库路径
            asn_db_path: GeoIP2 ASN数据库路径
        """
        self._geo_reader = None
        self._asn_reader = None
        self._cdn_ip_ranges = {}
        
        # 初始化GeoIP2数据库
        if GEOIP_AVAILABLE:
            self._init_geo_db(geo_db_path)
            self._init_asn_db(asn_db_path)
        
        # 加载CDN IP范围
        self._load_cdn_ip_ranges()
    
    def _init_geo_db(self, db_path: Optional[str]) -> None:
        """
        初始化GeoIP2城市数据库
        
        Args:
            db_path: 数据库路径
        """
        if not db_path:
            # 尝试默认路径
            default_paths = [
                'data/geoip/GeoLite2-City.mmdb',
                os.path.join(os.path.dirname(__file__), '../../data/geoip/GeoLite2-City.mmdb')
            ]
            
            for path in default_paths:
                if os.path.exists(path):
                    db_path = path
                    break
        
        if db_path and os.path.exists(db_path):
            try:
                self._geo_reader = geoip2.database.Reader(db_path)
                logger.info(f"已加载GeoIP2城市数据库: {db_path}")
            except Exception as e:
                logger.error(f"加载GeoIP2城市数据库失败: {str(e)}")
        else:
            logger.warning("GeoIP2城市数据库不可用")
    
    def _init_asn_db(self, db_path: Optional[str]) -> None:
        """
        初始化GeoIP2 ASN数据库
        
        Args:
            db_path: 数据库路径
        """
        if not db_path:
            # 尝试默认路径
            default_paths = [
                'data/geoip/GeoLite2-ASN.mmdb',
                os.path.join(os.path.dirname(__file__), '../../data/geoip/GeoLite2-ASN.mmdb')
            ]
            
            for path in default_paths:
                if os.path.exists(path):
                    db_path = path
                    break
        
        if db_path and os.path.exists(db_path):
            try:
                self._asn_reader = geoip2.database.Reader(db_path)
                logger.info(f"已加载GeoIP2 ASN数据库: {db_path}")
            except Exception as e:
                logger.error(f"加载GeoIP2 ASN数据库失败: {str(e)}")
        else:
            logger.warning("GeoIP2 ASN数据库不可用")
    
    def _load_cdn_ip_ranges(self) -> None:
        """加载CDN IP范围数据"""
        # 这里可以从文件或数据库加载CDN提供商的IP范围
        # 示例数据
        self._cdn_ip_ranges = {
            'cloudflare': [
                '103.21.244.0/22',
                '103.22.200.0/22',
                '103.31.4.0/22',
                '104.16.0.0/12',
                '108.162.192.0/18',
                '131.0.72.0/22',
                '141.101.64.0/18',
                '162.158.0.0/15',
                '172.64.0.0/13',
                '173.245.48.0/20',
                '188.114.96.0/20',
                '190.93.240.0/20',
                '197.234.240.0/22',
                '198.41.128.0/17'
            ],
            'akamai': [
                '23.32.0.0/11',
                '23.64.0.0/14',
                '104.64.0.0/10'
            ],
            'fastly': [
                '23.235.32.0/20',
                '43.249.72.0/22',
                '103.244.50.0/24',
                '151.101.0.0/16',
                '157.52.64.0/18',
                '172.111.64.0/18',
                '185.31.16.0/22',
                '199.27.72.0/21'
            ],
            'amazon_cloudfront': [
                '13.32.0.0/15',
                '52.84.0.0/15',
                '54.182.0.0/16',
                '54.192.0.0/16',
                '54.230.0.0/16',
                '54.239.128.0/18',
                '54.239.192.0/19',
                '99.84.0.0/16',
                '205.251.192.0/19',
                '204.246.164.0/22',
                '204.246.168.0/22',
                '204.246.174.0/23',
                '204.246.176.0/20'
            ]
        }
        
        logger.info(f"已加载CDN IP范围数据: {len(self._cdn_ip_ranges)} 个提供商")
    
    def is_valid_ip(self, ip: str) -> bool:
        """
        检查是否为有效的IP地址
        
        Args:
            ip: IP地址字符串
            
        Returns:
            是否为有效的IP地址
        """
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False
    
    def is_cdn_ip(self, ip: str) -> Tuple[bool, Optional[str]]:
        """
        检查IP是否属于已知的CDN网络
        
        Args:
            ip: IP地址
            
        Returns:
            (是否为CDN IP, CDN提供商名称)
        """
        if not self.is_valid_ip(ip):
            return False, None
        
        ip_obj = ipaddress.ip_address(ip)
        
        for provider, ranges in self._cdn_ip_ranges.items():
            for ip_range in ranges:
                try:
                    if ip_obj in ipaddress.ip_network(ip_range):
                        return True, provider
                except ValueError:
                    continue
        
        return False, None
    
    def get_geo_info(self, ip: str) -> Dict[str, Any]:
        """
        获取IP地址的地理位置信息
        
        Args:
            ip: IP地址
            
        Returns:
            地理位置信息字典
        """
        if not self.is_valid_ip(ip):
            return {'error': 'Invalid IP address'}
        
        if not self._geo_reader:
            return {'error': 'GeoIP database not available'}
        
        try:
            response = self._geo_reader.city(ip)
            
            return {
                'country': {
                    'iso_code': response.country.iso_code,
                    'name': response.country.name,
                },
                'city': {
                    'name': response.city.name,
                },
                'location': {
                    'latitude': response.location.latitude,
                    'longitude': response.location.longitude,
                    'time_zone': response.location.time_zone,
                },
                'continent': {
                    'code': response.continent.code,
                    'name': response.continent.name,
                }
            }
        except geoip2.errors.AddressNotFoundError:
            return {'error': 'IP address not found in database'}
        except Exception as e:
            logger.error(f"获取地理位置信息失败: {str(e)}")
            return {'error': str(e)}
    
    def get_asn_info(self, ip: str) -> Dict[str, Any]:
        """
        获取IP地址的ASN信息
        
        Args:
            ip: IP地址
            
        Returns:
            ASN信息字典
        """
        if not self.is_valid_ip(ip):
            return {'error': 'Invalid IP address'}
        
        if not self._asn_reader:
            return {'error': 'ASN database not available'}
        
        try:
            response = self._asn_reader.asn(ip)
            
            return {
                'asn': response.autonomous_system_number,
                'organization': response.autonomous_system_organization,
            }
        except geoip2.errors.AddressNotFoundError:
            return {'error': 'IP address not found in database'}
        except Exception as e:
            logger.error(f"获取ASN信息失败: {str(e)}")
            return {'error': str(e)}
    
    def analyze_ip(self, ip: str) -> Dict[str, Any]:
        """
        分析IP地址，获取综合信息
        
        Args:
            ip: IP地址
            
        Returns:
            IP分析结果字典
        """
        if not self.is_valid_ip(ip):
            return {'error': 'Invalid IP address'}
        
        result = {
            'ip': ip,
            'is_valid': True,
            'geo': None,
            'asn': None,
            'is_cdn_ip': False,
            'cdn_provider': None
        }
        
        # 获取地理位置信息
        geo_info = self.get_geo_info(ip)
        if 'error' not in geo_info:
            result['geo'] = geo_info
        
        # 获取ASN信息
        asn_info = self.get_asn_info(ip)
        if 'error' not in asn_info:
            result['asn'] = asn_info
        
        # 检查是否为CDN IP
        is_cdn, provider = self.is_cdn_ip(ip)
        result['is_cdn_ip'] = is_cdn
        result['cdn_provider'] = provider
        
        return result
    
    def batch_analyze(self, ips: List[str]) -> List[Dict[str, Any]]:
        """
        批量分析多个IP地址
        
        Args:
            ips: IP地址列表
            
        Returns:
            IP分析结果列表
        """
        return [self.analyze_ip(ip) for ip in ips]
    
    def close(self) -> None:
        """关闭数据库连接"""
        if self._geo_reader:
            self._geo_reader.close()
        
        if self._asn_reader:
            self._asn_reader.close()
    
    def __del__(self) -> None:
        """析构函数，确保关闭数据库连接"""
        self.close() 