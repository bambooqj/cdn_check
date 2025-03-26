"""
CDN检测器 - 用于检测目标是否使用CDN
"""

import logging
import json
import os
import re
import ipaddress
from typing import Dict, List, Any, Optional, Tuple

logger = logging.getLogger(__name__)


def _check_cdn_indicators_in_headers(headers: Dict[str, str], rule: Dict[str, Any]) -> Tuple[bool, List[str]]:
    """
    检查HTTP头中是否包含特定CDN提供商的指标

    Args:
        headers: HTTP响应头
        rule: CDN规则

    Returns:
        (是否匹配, 匹配的指标列表)
    """
    if not headers:
        return False, []

    indicators = []

    # 检查特定HTTP头
    for header in rule.get('http_headers', []):
        header_lower = header.lower()
        for actual_header in headers:
            if header_lower in actual_header.lower():
                indicators.append(f"HTTP头匹配: {actual_header}={headers[actual_header]}")
                break

    # 检查Server头中的特定模式
    if 'server' in headers and 'server_patterns' in rule:
        server_value = headers['server'].lower()
        for pattern in rule.get('server_patterns', []):
            if pattern.lower() in server_value:
                indicators.append(f"Server头匹配: server={headers['server']} (模式: {pattern})")

    return len(indicators) > 0, indicators


def _check_cert_keywords(cert_info: Dict[str, Any], rule: Dict[str, Any]) -> Tuple[bool, List[str]]:
    """
    检查证书信息中是否包含关键词

    Args:
        cert_info: 完整的证书信息
        rule: CDN规则

    Returns:
        (是否匹配, 匹配的指标列表)
    """
    if not cert_info or not rule.get('cert_keywords'):
        return False, []

    indicators = []

    # 将证书信息转换为字符串以便搜索
    cert_str = json.dumps(cert_info, ensure_ascii=False).lower()

    # 检查每个关键词
    for keyword in rule.get('cert_keywords', []):
        if keyword.lower() in cert_str:
            indicators.append(f"证书信息包含关键词: {keyword}")

    return len(indicators) > 0, indicators


def _is_ip_in_range(ip: str, ip_range: str) -> bool:
    """
    检查IP是否在指定范围内

    Args:
        ip: IP地址
        ip_range: IP范围（CIDR格式）

    Returns:
        是否在范围内
    """
    try:
        return ipaddress.ip_address(ip) in ipaddress.ip_network(ip_range)
    except Exception as e:
        logger.error(f"IP范围检查出错: {str(e)}")
        return False


def _match_cname(cname: str, pattern: str) -> bool:
    """
    匹配CNAME和模式

    Args:
        cname: CNAME记录
        pattern: 匹配模式

    Returns:
        是否匹配
    """
    # 将CNAME和模式都转换为小写
    cname = cname.lower()
    pattern = pattern.lower()
    if cname.endswith('.'):
        cname = cname[:-1]
    # 如果模式以*开头，进行通配符匹配
    if pattern.startswith('*.'):
        domain_part = pattern[2:]  # 去掉*.
        # 检查是否是子域名
        return cname.endswith(domain_part)
    # 否则进行精确匹配
    else:
        return cname.endswith(pattern)


class CDNDetector:
    """CDN检测器，用于检测目标是否使用CDN"""
    
    _instance = None
    _rules_cache = {}  # 类级别的规则缓存
    
    def __new__(cls, rules_file: Optional[str] = None):
        """实现单例模式"""
        if cls._instance is None:
            cls._instance = super(CDNDetector, cls).__new__(cls)
            cls._instance._initialized = False
        return cls._instance
    
    def __init__(self, rules_file: Optional[str] = None):
        """
        初始化CDN检测器
        
        Args:
            rules_file: CDN规则文件路径
        """
        # 避免重复初始化
        if hasattr(self, '_initialized') and self._initialized:
            # 如果提供了新的规则文件，则重新加载规则
            if rules_file and rules_file != self._rules_file:
                self._rules_file = rules_file
                self._load_rules()
            return
            
        # 处理规则文件路径
        if rules_file is None:
            # 使用默认路径
            base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
            rules_dir = os.path.join(base_dir, "data", "cdn")
            os.makedirs(rules_dir, exist_ok=True)
            rules_file = os.path.join(rules_dir, "rules.json")
        
        self._rules_file = rules_file
        self._rules = []
        self._ip_ranges = {}  # 缓存IP范围检查结果
        self._cname_patterns = {}  # 缓存CNAME模式检查结果
        
        # 加载规则
        self._load_rules()
        self._initialized = True
        
        self._http_header_rules = []
        
        # 加载配置文件
        try:
            with open('config.json', 'r', encoding='utf-8') as f:
                config = json.load(f)
                self._http_header_rules = config.get('httpheader_check', [])
                logger.info(f"成功加载 {len(self._http_header_rules)} 条HTTP头检测规则")
        except Exception as e:
            logger.error(f"加载HTTP头检测规则失败: {str(e)}")
        
        # 尝试加载 CDN.JSON
        cdn_json_path = os.path.join('data', 'cdn', 'CDN.JSON')
        if os.path.exists(cdn_json_path):
            self._load_cdn_json(cdn_json_path)
            
        # 添加常见CDN提供商的规则
        self._add_common_cdn_rules()
    
    def _add_common_cdn_rules(self) -> None:
        """添加常见CDN提供商的规则"""
        common_rules = [
            {
                'name': 'Akamai',
                'cname_patterns': [
                    '*.akamai.net',
                    '*.akamaiedge.net',
                    '*.akamaihd.net',
                    '*.akamaized.net',
                    '*.edgesuite.net',
                    '*.edgekey.net',
                    '*.srip.net',
                    '*.akamaitechnologies.com',
                    '*.akamaitechnologies.fr',
                    '*.akamaized.net',
                    '*.deploy.static.akamaitechnologies.com',
                    '*.akamai.com'
                ],
                'http_headers': [
                    'X-Akamai-Transformed',
                    'X-Akamai-SSL-Client-Sid',
                    'X-Akamai-Staging',
                    'X-Akamai-Request-ID',
                    'X-Akamai-Cache-On',
                    'X-Akamai-Cache-Remote-On',
                    'X-Check-Cacheable',
                    'X-Cache-Key',
                    'X-True-Cache-Key',
                    'X-Serial',
                    'X-Edge-IP'
                ],
                'cert_keywords': [
                    'akamai',
                    'edgekey',
                    'edgesuite',
                    'akamaitechnologies'
                ],
                'server_patterns': [
                    'AkamaiGHost',
                    'Akamai'
                ]
            },
            {
                'name': 'Cloudflare',
                'cname_patterns': [
                    '*.cloudflare.com',
                    '*.cloudflare.net',
                    '*.cloudflaressl.com',
                    '*.cloudflare-dns.com'
                ],
                'http_headers': [
                    'CF-Ray',
                    'CF-Cache-Status',
                    'CF-Worker',
                    'CF-Connecting-IP',
                    'CF-IPCountry'
                ],
                'cert_keywords': [
                    'cloudflare',
                    'sni.cloudflaressl.com'
                ],
                'server_patterns': [
                    'cloudflare'
                ]
            },
            {
                'name': 'Fastly',
                'cname_patterns': [
                    '*.fastly.net',
                    '*.fastlylb.net',
                    '*.fastly.com'
                ],
                'http_headers': [
                    'X-Served-By',
                    'X-Timer',
                    'X-Fastly-Request-ID',
                    'Fastly-Debug-Digest',
                    'Fastly-Debug-Path',
                    'Fastly-Debug-TTL'
                ],
                'cert_keywords': [
                    'fastly'
                ],
                'server_patterns': [
                    'fastly'
                ]
            },
            {
                'name': 'Amazon CloudFront',
                'cname_patterns': [
                    '*.cloudfront.net',
                    '*.amazonaws.com'
                ],
                'http_headers': [
                    'X-Amz-Cf-Id',
                    'X-Amz-Cf-Pop'
                ],
                'cert_keywords': [
                    'cloudfront',
                    'amazonaws'
                ],
                'server_patterns': [
                    'cloudfront',
                    'amazon'
                ]
            },
            {
                'name': 'Azure CDN',
                'cname_patterns': [
                    '*.azureedge.net',
                    '*.msecnd.net',
                    '*.azure.com'
                ],
                'http_headers': [
                    'X-Azure-Ref',
                    'X-Azure-DebugInfo',
                    'X-MSEdge-Ref'
                ],
                'cert_keywords': [
                    'azure',
                    'msecnd'
                ],
                'server_patterns': [
                    'microsoft',
                    'azure'
                ]
            },
            {
                'name': 'Alibaba Cloud CDN',
                'cname_patterns': [
                    '*.alicdn.com',
                    '*.kunlunca.com',
                    '*.kunlunea.com',
                    '*.kunlunso.com',
                    '*.kunlunwe.com',
                    '*.kunlunar.com',
                    '*.kunlunno.com',
                    '*.kunlunaq.com',
                    '*.kunlunpi.com',
                    '*.kunlunra.com',
                    '*.kunlungr.com',
                    '*.kunlunhuf.com',
                    '*.kunlunsl.com',
                    '*.kunlunar.com'
                ],
                'http_headers': [
                    'X-AliCDN',
                    'X-Swift-CacheTime'
                ],
                'cert_keywords': [
                    'alibaba',
                    'alicdn'
                ],
                'server_patterns': [
                    'tengine',
                    'aliyun'
                ]
            }
        ]
        
        for rule in common_rules:
            self.add_rule(rule)
            logger.info(f"添加常见CDN规则: {rule['name']}")
    
    def add_rule(self, rule: Dict[str, Any]) -> None:
        """
        添加CDN规则
        
        Args:
            rule: CDN规则
        """
        # 检查规则是否已存在
        for existing_rule in self._rules:
            if existing_rule['name'] == rule['name']:
                # 合并规则
                for key, value in rule.items():
                    if key != 'name':
                        if isinstance(value, list):
                            # 对于列表类型的字段，合并并去重
                            existing_values = existing_rule.get(key, [])
                            existing_rule[key] = list(set(existing_values + value))
                        else:
                            # 对于其他类型的字段，直接覆盖
                            existing_rule[key] = value
                logger.info(f"更新规则: {rule['name']}")
                return
        
        # 如果规则不存在，则添加
        self._rules.append(rule)
        logger.info(f"添加规则: {rule['name']}")
    
    def _load_rules(self) -> None:
        """加载CDN规则"""
        # 检查缓存
        if self._rules_file in self._rules_cache:
            self._rules = self._rules_cache[self._rules_file]
            logger.info(f"从缓存加载 {len(self._rules)} 条规则")
            return
            
        if not os.path.exists(self._rules_file):
            logger.warning(f"规则文件不存在: {self._rules_file}")
            return
        
        try:
            with open(self._rules_file, 'r', encoding='utf-8') as f:
                self._rules = json.load(f)
            
            # 更新缓存
            self._rules_cache[self._rules_file] = self._rules
            
            # 清除IP和CNAME缓存
            self._ip_ranges = {}
            self._cname_patterns = {}
            
            logger.info(f"已加载 {len(self._rules)} 条规则")
        except Exception as e:
            logger.error(f"加载规则文件失败: {str(e)}")

    def _check_http_headers(self, headers: Dict[str, str]) -> Tuple[bool, List[str]]:
        """
        检查HTTP头是否包含CDN特征
        
        Args:
            headers: HTTP响应头
            
        Returns:
            (是否匹配, 匹配的指标列表)
        """
        if not headers or not self._http_header_rules:
            return False, []
            
        indicators = []
        
        # 将所有header名称和值转换为小写
        headers_lower = {k.lower(): v.lower() for k, v in headers.items()}
        
        for rule in self._http_header_rules:
            header = rule['header'].lower()
            if header in headers_lower:
                value = headers_lower[header]
                for pattern in rule['patterns']:
                    if re.search(pattern.lower(), value):
                        indicators.append(f"HTTP头特征匹配: {rule['header']}={value} ({rule['description']})")
                        break
        
        # 检查Server头中的CDN特征
        if 'server' in headers_lower:
            server_value = headers_lower['server']
            cdn_keywords = [
                ('akamai', 'Akamai'),
                ('cloudflare', 'Cloudflare'),
                ('cloudfront', 'Amazon CloudFront'),
                ('fastly', 'Fastly'),
                ('azure', 'Azure CDN'),
                ('aliyun', 'Alibaba Cloud CDN'),
                ('cdn', '可能是CDN')
            ]
            
            for keyword, provider in cdn_keywords:
                if keyword in server_value:
                    indicators.append(f"Server头特征匹配: server={server_value} ({provider})")
        
        # 检查Via头中的CDN特征
        if 'via' in headers_lower:
            via_value = headers_lower['via']
            cdn_keywords = [
                ('akamai', 'Akamai'),
                ('cloudflare', 'Cloudflare'),
                ('cloudfront', 'Amazon CloudFront'),
                ('fastly', 'Fastly'),
                ('varnish', 'Varnish'),
                ('cdn', '可能是CDN')
            ]
            
            for keyword, provider in cdn_keywords:
                if keyword in via_value:
                    indicators.append(f"Via头特征匹配: via={via_value} ({provider})")
        
        return len(indicators) > 0, indicators

    def detect(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """检测是否使用CDN"""
        # 打印输入数据
        logger.info("开始CDN检测，输入数据:")
        logger.info(f"域名: {data.get('domain')}")
        logger.info(f"IP列表: {data.get('ips', [])}")
        logger.info(f"CNAME链: {data.get('cname_chain', [])}")
        logger.info(f"HTTP头: {data.get('http_headers', {})}")
        if data.get('cert'):
            logger.info(f"证书信息: {json.dumps(data.get('cert'), indent=2, ensure_ascii=False)}")
        
        scores = {}
        indicators = {}
        generic_cdn_indicators = []
        
        # 预处理CNAME链，确保所有CNAME都是小写的
        cname_chain = [cname.lower() for cname in data.get('cname_chain', [])]
        
        # 首先检查通用HTTP头特征
        has_generic_headers, header_indicators = self._check_http_headers(data.get('http_headers', {}))
        if has_generic_headers:
            generic_cdn_indicators.extend(header_indicators)
            logger.info("检测到通用CDN特征:")
            for indicator in header_indicators:
                logger.info(f"  {indicator}")
        
        # 检查HTTP插件提供的CDN指标
        http_plugin_data = data.get('http_plugin', {})
        if http_plugin_data and 'cdn_indicators' in http_plugin_data:
            cdn_indicators = http_plugin_data.get('cdn_indicators', [])
            if cdn_indicators:
                for indicator in cdn_indicators:
                    provider = indicator.get('provider')
                    header = indicator.get('header')
                    value = indicator.get('value')
                    
                    if provider and provider != '可能是CDN':
                        # 如果有明确的提供商，直接增加得分
                        if provider not in scores:
                            scores[provider] = 0.0

                        scores[provider] += 0.3
                        
                        if provider not in indicators:
                            indicators[provider] = []
                        
                        indicators[provider].append(f"HTTP插件检测到CDN: {header}={value} ({provider})")
                        logger.info(f"HTTP插件检测到CDN: {header}={value} ({provider}), 得分: {scores[provider]}")
                    else:
                        # 否则添加到通用指标
                        generic_cdn_indicators.append(f"HTTP插件检测到可能的CDN: {header}={value}")
                        logger.info(f"HTTP插件检测到可能的CDN: {header}={value}")
        
        # 对每个规则进行检测
        for rule in self._rules:
            provider = rule['name']
            logger.info(f"\n正在检查规则: {provider}")
            if provider not in scores:
                scores[provider] = 0.0
                
            provider_indicators = []
            
            # CNAME模式匹配
            for cname in cname_chain:
                for pattern in rule.get('cname_patterns', []):
                    pattern_lower = pattern.lower()
                    logger.info(f"对比CNAME: {cname} 与模式: {pattern_lower}")
                    
                    # 使用_match_cname进行匹配
                    if _match_cname(cname, pattern_lower):
                        scores[provider] += 0.6
                        provider_indicators.append(f"CNAME匹配: {cname} -> {pattern}")
                        logger.info(f"CNAME匹配成功! 得分: {scores[provider]}")
                        break
            
            # IP范围匹配
            for ip in data.get('ips', []):
                for ip_range in rule.get('ip_ranges', []):
                    logger.info(f"检查IP: {ip} 是否在范围: {ip_range}")
                    try:
                        if _is_ip_in_range(ip, ip_range):
                            scores[provider] += 0.3
                            provider_indicators.append(f"IP匹配: {ip} -> {ip_range}")
                            logger.info(f"IP匹配成功! 得分: {scores[provider]}")
                            break
                    except Exception as e:
                        logger.error(f"IP范围检查出错: {str(e)}")
            
            # HTTP头部匹配
            headers = data.get('http_headers', {})
            has_headers, header_indicators = _check_cdn_indicators_in_headers(headers, rule)
            if has_headers:
                scores[provider] += 0.3
                provider_indicators.extend(header_indicators)
                logger.info(f"HTTP头匹配成功! 得分: {scores[provider]}")
            
            # 证书关键词匹配
            if data.get('cert'):
                has_cert, cert_indicators = _check_cert_keywords(data['cert'], rule)
                if has_cert:
                    scores[provider] += 0.3
                    provider_indicators.extend(cert_indicators)
                    logger.info(f"证书关键词匹配成功! 得分: {scores[provider]}")
            
            if provider_indicators:
                indicators[provider] = provider_indicators

        # 选择得分最高的提供商
        if scores:
            max_score = max(scores.values())
            max_providers = [p for p, s in scores.items() if s == max_score]
            
            logger.info("\n检测结果:")
            logger.info(f"所有得分: {scores}")
            logger.info(f"最高得分: {max_score}")
            logger.info(f"最高得分提供商: {max_providers}")
            
            if max_score >= 0.3:  # 置信度阈值
                provider = max_providers
                if max_score == 0.3:
                    provider = "UnknownCDN"
                return {
                    'is_cdn': True,
                    'cdn_provider': provider,
                    'confidence': max_score,
                    'indicators': indicators.get(provider[0], [])
                }
        # 如果没有匹配到具体CDN提供商，但检测到通用CDN特征
        if generic_cdn_indicators:
            logger.info("未匹配到具体CDN提供商，但检测到通用CDN特征")
            return {
                'is_cdn': True,
                'cdn_provider': "UnknownCDN",
                'confidence': 0.3,  # 基于通用特征的置信度
                'indicators': generic_cdn_indicators
            }

        
        logger.info("未检测到CDN")
        return {
            'is_cdn': False,
            'cdn_provider': None,
            'confidence': 0.0,
            'indicators': []
        }
    
    def _load_cdn_json(self, file_path: str) -> None:
        """
        加载 CDN.JSON 格式的规则文件
        
        Args:
            file_path: CDN.JSON 文件路径
        """
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                
            if not isinstance(data, dict) or 'Item' not in data:
                logger.warning(f"CDN.JSON 格式无效: {file_path}")
                return

            for item in data['Item']:
                if not all(k in item for k in ['Domain', 'Name']):
                    continue
                    
                # 转换为标准规则格式
                rule = {
                    'name': item['Name'],
                    'cname_patterns': [item['Domain']],
                    'ip_ranges': [],  # CDN.JSON 中没有 IP 范围信息
                    'http_headers': [],  # 可以根据需要添加特定的 HTTP 头
                    'cert_keywords': [
                        item['Domain'].lower(),  # 域名作为关键词
                    ]
                }
                
                # 添加规则（会自动合并相同名称的规则）
                self.add_rule(rule)
                
            logger.info(f"从 {file_path} 加载了 {len(data['Item'])} 条 CDN 规则")
        except Exception as e:
            logger.error(f"加载 CDN.JSON 失败: {str(e)}")

