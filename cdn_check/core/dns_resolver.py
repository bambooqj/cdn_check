"""
DNS解析引擎 - 用于解析域名并获取CNAME链
"""

import dns.resolver
import dns.exception
import logging
import socket
from typing import Dict, List, Any
from cachetools import TTLCache

logger = logging.getLogger(__name__)

class DNSResolver:
    """DNS解析器，用于解析域名并获取CNAME链"""
    
    def __init__(self, cache_size: int = 1000, cache_ttl: int = 300):
        """
        初始化DNS解析器
        
        Args:
            cache_size: 缓存大小
            cache_ttl: 缓存TTL（秒）
        """
        self._resolver = dns.resolver.Resolver()
        self._resolver.timeout = 5.0
        self._resolver.lifetime = 10.0
        
        # 设置默认DNS服务器
        self._resolver.nameservers = ['8.8.8.8', '8.8.4.4']
        
        # 初始化缓存
        self._cache = TTLCache(maxsize=cache_size, ttl=cache_ttl)
    
    def set_nameservers(self, nameservers: List[str]) -> None:
        """
        设置自定义DNS服务器
        
        Args:
            nameservers: DNS服务器列表
        """
        if nameservers:
            self._resolver.nameservers = nameservers
            logger.info(f"设置DNS服务器: {nameservers}")
    
    def resolve(self, domain: str, max_cname_depth: int = 5) -> Dict[str, Any]:
        """
        解析域名，获取A记录和CNAME链
        
        Args:
            domain: 要解析的域名
            max_cname_depth: 最大CNAME链深度
            
        Returns:
            包含解析结果的字典
        """
        # 检查缓存
        if domain in self._cache:
            logger.info(f"使用缓存的DNS结果: {domain}")
            return self._cache[domain]
        
        logger.info(f"开始解析域名: {domain}")
        
        result = {
            'domain': domain,
            'a_records': [],
            'aaaa_records': [],
            'cname_chain': [],
            'mx_records': [],
            'ns_records': [],
            'txt_records': [],
            'errors': []
        }
        
        # 检查域名是否为IP地址
        try:
            socket.inet_aton(domain)
            # 如果是IP地址，直接返回
            result['a_records'] = [domain]
            logger.info(f"域名是IP地址: {domain}")
            return result
        except:
            pass
        
        # 解析CNAME链和A记录
        try:
            # 设置更长的超时时间
            self._resolver.timeout = 10.0
            self._resolver.lifetime = 15.0
            
            # 先尝试直接解析A记录
            try:
                a_records = self._resolver.resolve(domain, 'A')
                result['a_records'] = [str(r) for r in a_records]
                logger.info(f"解析到A记录: {result['a_records']}")
            except dns.resolver.NoAnswer:
                logger.info(f"没有A记录: {domain}")
            except Exception as e:
                error_msg = f"A记录解析错误: {str(e)}"
                result['errors'].append(error_msg)
                logger.warning(error_msg)
            
            # 解析CNAME链
            current_domain = domain
            cname_depth = 0
            
            while cname_depth < max_cname_depth:
                try:
                    # 尝试获取CNAME记录
                    answers = self._resolver.resolve(current_domain, 'CNAME')
                    if not answers:
                        break
                    
                    # 获取CNAME目标
                    cname_target = str(answers[0].target)
                    result['cname_chain'].append(cname_target)
                    logger.info(f"解析到CNAME: {current_domain} -> {cname_target}")
                    
                    # 更新当前域名为CNAME目标
                    current_domain = cname_target
                    cname_depth += 1
                    
                    # 如果没有A记录，尝试解析CNAME目标的A记录
                    if not result['a_records']:
                        try:
                            a_records = self._resolver.resolve(current_domain, 'A')
                            result['a_records'] = [str(r) for r in a_records]
                            logger.info(f"从CNAME目标解析到A记录: {result['a_records']}")
                        except Exception:
                            pass
                except dns.resolver.NoAnswer:
                    # 没有CNAME记录，结束链
                    logger.info(f"没有更多CNAME记录: {current_domain}")
                    break
                except Exception as e:
                    error_msg = f"CNAME解析错误: {str(e)}"
                    result['errors'].append(error_msg)
                    logger.warning(error_msg)
                    break
            
            # 如果没有A记录也没有CNAME，尝试使用不同的DNS服务器
            if not result['a_records'] and not result['cname_chain']:
                logger.info(f"尝试使用备用DNS服务器解析: {domain}")
                # 尝试使用公共DNS服务器
                backup_nameservers = ['8.8.8.8', '114.114.114.114', '1.1.1.1']
                original_nameservers = self._resolver.nameservers
                
                for ns in backup_nameservers:
                    if ns in original_nameservers:
                        continue
                        
                    try:
                        logger.info(f"尝试使用DNS服务器 {ns} 解析: {domain}")
                        self._resolver.nameservers = [ns]
                        
                        # 尝试解析A记录
                        try:
                            a_records = self._resolver.resolve(domain, 'A')
                            result['a_records'] = [str(r) for r in a_records]
                            logger.info(f"使用DNS服务器 {ns} 解析到A记录: {result['a_records']}")
                            if result['a_records']:
                                break
                        except Exception as e:
                            logger.warning(f"使用DNS服务器 {ns} 解析A记录失败: {str(e)}")
                        
                        # 尝试解析CNAME
                        try:
                            cname_records = self._resolver.resolve(domain, 'CNAME')
                            if cname_records:
                                cname = str(cname_records[0].target)
                                result['cname_chain'].append(cname)
                                logger.info(f"使用DNS服务器 {ns} 解析到CNAME: {domain} -> {cname}")
                                
                                # 尝试解析CNAME目标的A记录
                                try:
                                    a_records = self._resolver.resolve(cname, 'A')
                                    result['a_records'] = [str(r) for r in a_records]
                                    logger.info(f"使用DNS服务器 {ns} 从CNAME目标解析到A记录: {result['a_records']}")
                                except Exception as e:
                                    logger.warning(f"使用DNS服务器 {ns} 解析CNAME目标的A记录失败: {str(e)}")
                                
                                break
                        except Exception as e:
                            logger.warning(f"使用DNS服务器 {ns} 解析CNAME失败: {str(e)}")
                    except Exception as e:
                        logger.warning(f"使用DNS服务器 {ns} 解析失败: {str(e)}")
                    finally:
                        # 恢复原始DNS服务器
                        self._resolver.nameservers = original_nameservers
        except Exception as e:
            error_msg = f"DNS解析错误: {str(e)}"
            result['errors'].append(error_msg)
            logger.error(error_msg)
        
        # 解析AAAA记录
        try:
            aaaa_records = self._resolver.resolve(domain, 'AAAA')
            result['aaaa_records'] = [str(r) for r in aaaa_records]
            logger.info(f"解析到AAAA记录: {result['aaaa_records']}")
        except dns.resolver.NoAnswer:
            logger.info(f"没有AAAA记录: {domain}")
        except Exception as e:
            error_msg = f"AAAA记录解析错误: {str(e)}"
            result['errors'].append(error_msg)
            logger.warning(error_msg)
        
        # 解析MX记录
        try:
            mx_records = self._resolver.resolve(domain, 'MX')
            result['mx_records'] = [f"{r.preference} {str(r.exchange)}" for r in mx_records]
            logger.info(f"解析到MX记录: {result['mx_records']}")
        except dns.resolver.NoAnswer:
            logger.info(f"没有MX记录: {domain}")
        except Exception as e:
            error_msg = f"MX记录解析错误: {str(e)}"
            result['errors'].append(error_msg)
            logger.warning(error_msg)
        
        # 解析NS记录
        try:
            ns_records = self._resolver.resolve(domain, 'NS')
            result['ns_records'] = [str(r) for r in ns_records]
            logger.info(f"解析到NS记录: {result['ns_records']}")
        except dns.resolver.NoAnswer:
            logger.info(f"没有NS记录: {domain}")
        except Exception as e:
            error_msg = f"NS记录解析错误: {str(e)}"
            result['errors'].append(error_msg)
            logger.warning(error_msg)
        
        # 解析TXT记录
        try:
            txt_records = self._resolver.resolve(domain, 'TXT')
            result['txt_records'] = [str(r) for r in txt_records]
            logger.info(f"解析到TXT记录: {result['txt_records']}")
        except dns.resolver.NoAnswer:
            logger.info(f"没有TXT记录: {domain}")
        except Exception as e:
            error_msg = f"TXT记录解析错误: {str(e)}"
            result['errors'].append(error_msg)
            logger.warning(error_msg)
        
        # 缓存结果
        self._cache[domain] = result

        logger.info(f"DNS解析完成: {domain}")
        return result
    
    def clear_cache(self) -> None:
        """清除DNS缓存"""
        self._cache.clear()
        logger.info("已清除DNS缓存")
    
    def get_cache_stats(self) -> Dict[str, int]:
        """
        获取缓存统计信息
        
        Returns:
            包含缓存统计信息的字典
        """
        return {
            'size': len(self._cache),
            'maxsize': self._cache.maxsize,
            'ttl': self._cache.ttl
        } 