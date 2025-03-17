"""
证书分析器模块 - 用于分析SSL/TLS证书并提取特征
"""

import ssl
import socket
import logging
import json
import os
from typing import Dict, Any, List, Optional, Tuple, Union
from datetime import datetime
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import NameOID

logger = logging.getLogger(__name__)

class CertAnalyzer:
    """证书分析器，用于分析SSL/TLS证书并提取特征"""

    def __init__(self, timeout: int = 10, port: int = 443, rules_file: Optional[str] = None):
        """
        初始化证书分析器
        
        Args:
            timeout: 连接超时时间（秒）
            port: 默认端口号
            rules_file: CDN规则文件路径
        """
        self._timeout = timeout
        self._port = port
        self._rules = []
        self._cdn_keywords = {
            'cloudflare': 'Cloudflare',
            'akamai': 'Akamai',
            'fastly': 'Fastly',
            'amazon': 'Amazon CloudFront',
            'azure': 'Azure CDN',
            'cloudfront': 'Amazon CloudFront',
            'cdn': 'Generic CDN',
            'incapsula': 'Imperva Incapsula',
            'limelight': 'Limelight Networks',
            'edgecast': 'Edgecast/Verizon',
            'stackpath': 'StackPath',
            'keycdn': 'KeyCDN',
            'sucuri': 'Sucuri',
            'bunny': 'BunnyCDN',
            'alibaba': 'Alibaba Cloud CDN',
            'tencent': 'Tencent Cloud CDN',
            'baidu': 'Baidu Cloud CDN'
        }

        # 加载规则
        if rules_file:
            self._load_rules(rules_file)
        else:
            # 尝试从默认路径加载规则
            default_paths = [
                'data/cdn/rules.json',
                os.path.join(os.path.dirname(__file__), '../../data/cdn/rules.json')
            ]
            for path in default_paths:
                if os.path.exists(path):
                    self._load_rules(path)
                    break

    def _load_rules(self, rules_file: str) -> None:
        """
        加载CDN规则
        
        Args:
            rules_file: 规则文件路径
        """
        try:
            with open(rules_file, 'r', encoding='utf-8') as f:
                self._rules = json.load(f)
            logger.info(f"已加载 {len(self._rules)} 条CDN规则")
        except Exception as e:
            logger.error(f"加载CDN规则失败: {str(e)}")

    def get_certificate(self, hostname: str, port: Optional[int] = None) -> Dict[str, Any]:
        """
        获取SSL/TLS证书
        
        Args:
            hostname: 主机名
            port: 端口号，如果为None则使用默认端口
            
        Returns:
            证书信息字典
        """
        if port is None:
            port = self._port

        result = {
            'success': False,
            'hostname': hostname,
            'port': port,
            'cert': None,
            'error': None
        }

        # 空证书模板
        empty_cert = {
            'subject': {},
            'issuer': {},
            'version': None,
            'serialNumber': None,
            'notBefore': None,
            'notAfter': None,
            'subjectAltName': []
        }

        # 重试机制
        max_retries = 3
        for retry in range(max_retries):
            try:
                # 创建SSL上下文，完全禁用证书验证
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                
                # 禁用所有证书验证选项
                context.options |= ssl.OP_NO_SSLv2
                context.options |= ssl.OP_NO_SSLv3
                context.options |= ssl.OP_NO_COMPRESSION
                context.check_hostname = False
                
                # 不验证证书
                context.verify_flags = ssl.VERIFY_DEFAULT

                # 增加超时时间
                timeout = self._timeout * (retry + 1)

                # 建立连接
                with socket.create_connection((hostname, port), timeout=timeout) as sock:
                    with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                        # 获取证书
                        cert_der = ssock.getpeercert(binary_form=True)
                        if not cert_der:
                            logger.warning(f"未获取到证书内容: {hostname}:{port} (重试 {retry+1}/{max_retries})")
                            continue

                        # 解析证书
                        cert = x509.load_der_x509_certificate(cert_der)
                        cert_info = self._parse_certificate(cert)

                        # 更新结果
                        result.update({
                            'success': True,
                            'cert': cert_info
                        })

                        logger.info(f"成功获取证书: {hostname}:{port}")
                        return result

            except socket.timeout:
                logger.warning(f"连接超时: {hostname}:{port} (重试 {retry+1}/{max_retries})")
            except socket.error as e:
                logger.warning(f"连接错误: {hostname}:{port} - {str(e)} (重试 {retry+1}/{max_retries})")
            except ssl.SSLError as e:
                logger.warning(f"SSL错误: {hostname}:{port} - {str(e)} (重试 {retry+1}/{max_retries})")
            except Exception as e:
                logger.warning(f"获取证书失败: {hostname}:{port} - {str(e)} (重试 {retry+1}/{max_retries})")

        # 所有重试都失败
        result['error'] = f"无法获取证书，已重试 {max_retries} 次"
        result['cert'] = empty_cert
        logger.error(f"获取证书失败: {hostname}:{port} - {result['error']}")
        return result

    def _parse_certificate(self, cert: x509.Certificate) -> Dict[str, Any]:
        """
        解析X.509证书
        
        Args:
            cert: X.509证书对象
            
        Returns:
            证书信息字典
        """
        def parse_name(name: x509.Name) -> Dict[str, str]:
            """解析证书名称"""
            result = {}
            for attr in name:
                oid_name = attr.oid._name
                value = attr.value
                result[oid_name] = value
            return result

        # 解析基本信息，使用兼容性更好的API
        try:
            # 尝试使用新版API
            not_before = cert.not_valid_before_utc.isoformat()
            not_after = cert.not_valid_after_utc.isoformat()
        except AttributeError:
            # 回退到旧版API
            try:
                not_before = cert.not_valid_before.isoformat()
                not_after = cert.not_valid_after.isoformat()
            except AttributeError:
                # 最后的回退方案
                not_before = str(cert.not_valid_before)
                not_after = str(cert.not_valid_after)

        cert_info = {
            'subject': parse_name(cert.subject),
            'issuer': parse_name(cert.issuer),
            'version': cert.version.value,
            'serialNumber': format(cert.serial_number, 'x'),
            'notBefore': not_before,
            'notAfter': not_after,
            'subjectAltName': [],
            'fingerprint': {
                'sha1': cert.fingerprint(hashes.SHA1()).hex(),
                'sha256': cert.fingerprint(hashes.SHA256()).hex()
            }
        }

        # 提取常见主题字段
        subject_fields = {
            'commonName': NameOID.COMMON_NAME,
            'organization': NameOID.ORGANIZATION_NAME,
            'organizationalUnit': NameOID.ORGANIZATIONAL_UNIT_NAME,
            'country': NameOID.COUNTRY_NAME,
            'locality': NameOID.LOCALITY_NAME,
            'state': NameOID.STATE_OR_PROVINCE_NAME
        }
        
        for field_name, oid in subject_fields.items():
            try:
                values = cert.subject.get_attributes_for_oid(oid)
                if values:
                    cert_info[field_name] = [attr.value for attr in values]
            except Exception:
                pass

        # 解析扩展
        try:
            for ext in cert.extensions:
                if ext.oid._name == 'subjectAltName':
                    for name in ext.value:
                        if isinstance(name, x509.DNSName):
                            cert_info['subjectAltName'].append(f"DNS:{name.value}")
                        elif isinstance(name, x509.IPAddress):
                            cert_info['subjectAltName'].append(f"IP:{name.value}")
        except Exception as e:
            logger.warning(f"解析证书扩展失败: {str(e)}")

        return cert_info

    def analyze_certificate(self, cert_info: Dict[str, Any]) -> Dict[str, Any]:
        """
        分析证书，检测CDN特征
        
        Args:
            cert_info: 证书信息
            
        Returns:
            CDN特征分析结果
        """
        result = {
            'is_cdn': False,
            'confidence': 0.0,
            'cdn_provider': None,
            'cdn_indicators': []
        }
        
        if not cert_info:
            return result
        
        # 检查证书颁发者
        issuer = cert_info.get('issuer', {})
        self._check_issuer(issuer, result)
        
        # 检查主题字段
        subject = cert_info.get('subject', {})
        self._check_subject(subject, result)
        
        # 检查备用名称数量
        alt_names = cert_info.get('subjectAltName', [])
        self._check_alt_names(alt_names, result)
        
        # 检查规则匹配
        self._check_rules(cert_info, result)
        
        return result
    
    def _check_issuer(self, issuer: Dict[str, str], result: Dict[str, Any]) -> None:
        """检查证书颁发者是否包含CDN关键字"""
        for key, value in issuer.items():
            if not isinstance(value, str):
                continue
                
            value_lower = value.lower()
            
            # 检查是否包含CDN关键字
            for keyword, provider in self._cdn_keywords.items():
                if keyword in value_lower:
                    result['is_cdn'] = True
                    result['confidence'] = 0.8
                    result['cdn_provider'] = provider
                    result['cdn_indicators'].append(f"证书颁发者包含CDN关键字: {value}")
                    return
    
    def _check_subject(self, subject: Dict[str, str], result: Dict[str, Any]) -> None:
        """检查证书主题是否包含CDN关键字"""
        for key, value in subject.items():
            if not isinstance(value, str):
                continue
                
            value_lower = value.lower()
            
            # 检查是否包含CDN关键字
            for keyword, provider in self._cdn_keywords.items():
                if keyword in value_lower:
                    result['is_cdn'] = True
                    result['confidence'] = max(result['confidence'], 0.7)
                    if not result['cdn_provider']:
                        result['cdn_provider'] = provider
                    result['cdn_indicators'].append(f"证书主题包含CDN关键字: {value}")
                    return
    
    def _check_alt_names(self, alt_names: List[str], result: Dict[str, Any]) -> None:
        """检查证书备用名称数量和内容"""
        # 检查备用名称数量
        if len(alt_names) > 5:  # 如果备用名称较多，可能是CDN
            result['is_cdn'] = True
            result['confidence'] = max(result['confidence'], 0.6)
            result['cdn_indicators'].append(f"证书包含多个备用名称: {len(alt_names)}个")
        
        # 检查备用名称是否包含CDN关键字
        for name in alt_names:
            name_lower = name.lower()
            for keyword, provider in self._cdn_keywords.items():
                if keyword in name_lower:
                    result['is_cdn'] = True
                    result['confidence'] = max(result['confidence'], 0.7)
                    if not result['cdn_provider']:
                        result['cdn_provider'] = provider
                    result['cdn_indicators'].append(f"证书备用名称包含CDN关键字: {name}")
                    return
    
    def _check_rules(self, cert_info: Dict[str, Any], result: Dict[str, Any]) -> None:
        """检查证书是否匹配CDN规则"""
        if not self._rules:
            return
            
        for rule in self._rules:
            provider = rule.get('name')
            cert_keywords = rule.get('cert_keywords', [])
            
            # 跳过没有证书关键字的规则
            if not cert_keywords:
                continue
                
            # 检查证书颁发者和主题
            issuer_str = json.dumps(cert_info.get('issuer', {})).lower()
            subject_str = json.dumps(cert_info.get('subject', {})).lower()
            alt_names_str = json.dumps(cert_info.get('subjectAltName', [])).lower()
            
            # 合并所有文本进行检查
            all_text = issuer_str + subject_str + alt_names_str
            
            for keyword in cert_keywords:
                keyword_lower = keyword.lower()
                if keyword_lower in all_text:
                    result['is_cdn'] = True
                    result['confidence'] = max(result['confidence'], 0.9)
                    result['cdn_provider'] = provider
                    result['cdn_indicators'].append(f"证书匹配CDN规则: {provider} (关键字: {keyword})")
                    return

    def close(self) -> None:
        """关闭分析器，释放资源"""
        pass 