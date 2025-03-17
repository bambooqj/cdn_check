"""
HTTP请求插件 - 用于获取目标网站的HTTP头和页面内容
"""

import requests
import logging
from typing import Dict, Any, List, Optional, Tuple
import time
import json
from urllib.parse import urlparse

from cdn_check.core.plugin_base import PluginBase
from cdn_check.core import get_logger

# 获取日志器
logger = get_logger(__name__)

class HTTPPlugin(PluginBase):
    """HTTP请求插件，用于获取目标网站的HTTP头和页面内容"""
    
    plugin_type = "requester"
    plugin_name = "http_requester"
    plugin_description = "HTTP请求插件，用于获取目标网站的HTTP头和页面内容"
    plugin_version = "0.1.0"
    plugin_author = "CDN检测工具"
    
    def __init__(self):
        super().__init__()
        self._session = requests.Session()
        self._timeout = 10  # 默认超时时间
        self._headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        }
    
    def execute(self, url: str, **kwargs) -> Dict[str, Any]:
        """
        执行HTTP请求
        
        Args:
            url: 目标URL
            **kwargs: 其他参数
                - method: 请求方法 (默认 GET)
                - headers: 自定义请求头
                - timeout: 请求超时时间
                - proxies: 代理设置
                - verify_ssl: 是否验证SSL证书
                - get_content: 是否获取页面内容
                - follow_redirects: 是否跟随重定向
                - max_redirects: 最大重定向次数
                
        Returns:
            HTTP请求结果
        """
        # 获取参数
        method = kwargs.get('method', 'GET')
        headers = kwargs.get('headers') or self.get_config('headers') or self._headers
        timeout = kwargs.get('timeout') or self.get_config('timeout') or self._timeout
        proxies = kwargs.get('proxies') or self.get_config('proxies')
        verify_ssl = kwargs.get('verify_ssl', True)
        get_content = kwargs.get('get_content', False)
        follow_redirects = kwargs.get('follow_redirects', True)
        max_redirects = kwargs.get('max_redirects', 5)
        
        # 添加协议前缀（如果没有）
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        
        result = {
            'plugin': self.plugin_name,
            'target': url,
            'success': True,
            'result': {
                'url': url,
                'status_code': None,
                'headers': {},
                'content_length': 0,
                'response_time': 0,
                'redirect_chain': [],
                'server': None,
                'content_type': None,
                'cdn_headers': []
            }
        }
        
        # 执行请求
        try:
            start_time = time.time()
            
            response = self._session.request(
                method=method,
                url=url,
                headers=headers,
                timeout=timeout,
                proxies=proxies,
                verify=verify_ssl,
                allow_redirects=follow_redirects
            )
            
            response_time = time.time() - start_time
            
            # 记录基本信息
            result['result']['status_code'] = response.status_code
            result['result']['headers'] = dict(response.headers)
            result['result']['content_length'] = len(response.content)
            result['result']['response_time'] = round(response_time, 3)
            result['result']['server'] = response.headers.get('Server')
            result['result']['content_type'] = response.headers.get('Content-Type')
            
            # 记录重定向链
            if hasattr(response, 'history') and response.history:
                for r in response.history:
                    result['result']['redirect_chain'].append({
                        'url': r.url,
                        'status_code': r.status_code,
                        'location': r.headers.get('Location')
                    })
            
            # 获取页面内容（如果需要）
            if get_content:
                result['result']['content'] = response.text
            
            # 检查可能的CDN相关头部
            cdn_headers = ['x-cdn', 'x-cache', 'x-served-by', 'x-amz-cf-id', 'x-edge-location',
                          'x-cache-hits', 'cf-ray', 'x-fastly', 'via', 'x-amz-cf-pop',
                          'x-powered-by-plesk', 'x-proxy-cache', 'x-cache-status']
            
            for header in cdn_headers:
                if header.lower() in response.headers:
                    result['result']['cdn_headers'].append({
                        'name': header.lower(),
                        'value': response.headers[header]
                    })
            
        except requests.RequestException as e:
            result['success'] = False
            result['error'] = str(e)
        
        # 调整返回结果格式以符合app.py的期望
        return {
            'success': result['success'],
            'result': result['result'],
            'error': result.get('error', None) if not result['success'] else None
        }
    
    def check_cdn_headers(self, headers: Dict[str, str]) -> List[Dict[str, str]]:
        """
        检查HTTP头中的CDN相关信息
        
        Args:
            headers: HTTP响应头
            
        Returns:
            CDN相关头部列表
        """
        result = []
        cdn_headers = ['x-cdn', 'x-cache', 'x-served-by', 'x-amz-cf-id', 'x-edge-location',
                      'x-cache-hits', 'cf-ray', 'x-fastly', 'via', 'x-amz-cf-pop',
                      'x-powered-by-plesk', 'x-proxy-cache', 'x-cache-status']
        
        for header in cdn_headers:
            if header.lower() in headers:
                result.append({
                    'name': header.lower(),
                    'value': headers[header]
                })
        
        return result
    
    def validate(self) -> bool:
        """
        验证插件配置是否有效
        
        Returns:
            配置是否有效
        """
        timeout = self.get_config('timeout')
        if timeout and not isinstance(timeout, (int, float)):
            return False
            
        proxies = self.get_config('proxies')
        if proxies and not isinstance(proxies, dict):
            return False
            
        return True
    
    def shutdown(self) -> None:
        """关闭HTTP请求插件"""
        if self._session:
            self._session.close()
        super().shutdown()
