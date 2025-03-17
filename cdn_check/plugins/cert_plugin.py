"""
证书分析插件 - 用于分析SSL/TLS证书
"""

from typing import Dict, Any, List, Optional, Tuple

from cdn_check.core.plugin_base import PluginBase
from cdn_check.core.cert_analyzer import CertAnalyzer
from cdn_check.core import get_logger

# 获取日志器
logger = get_logger(__name__)

class CertPlugin(PluginBase):
    """证书分析插件，用于分析SSL/TLS证书"""
    
    plugin_type = "analyzer"
    plugin_name = "cert_analyzer"
    plugin_description = "证书分析插件，用于分析SSL/TLS证书并检测CDN特征"
    plugin_version = "0.1.0"
    plugin_author = "CDN检测工具"
    
    def __init__(self):
        super().__init__()
        self._analyzer = None
    
    def initialize(self, config: Dict[str, Any]) -> bool:
        """初始化证书分析器"""
        try:
            # 使用传入的配置更新现有配置
            if config:
                self._config.update(config)
                
            # 获取配置
            port = self._config.get('port', 443)
            timeout = self._config.get('timeout', 10)
            rules_file = self._config.get('rules_file')
            
            # 初始化分析器
            self._analyzer = CertAnalyzer(timeout=timeout, port=port, rules_file=rules_file)
            logger.info(f"证书分析器初始化成功")
            return True
        except Exception as e:
            logger.error(f"证书分析器初始化失败: {str(e)}")
            return False
    
    def _execute(self, target: str, **kwargs) -> Dict[str, Any]:
        """
        执行证书分析
        
        Args:
            target: 目标主机名
            **kwargs: 其他参数
                - port: 端口号
                - timeout: 超时时间
                
        Returns:
            证书分析结果
        """
        # 获取参数，优先使用kwargs中的参数
        port = kwargs.get('port') or self._config.get('port', 443)
        timeout = kwargs.get('timeout') or self._config.get('timeout', 10)
        
        logger.info(f"开始分析目标 {target} 的证书，端口：{port}，超时：{timeout}秒")
        
        # 确保分析器已初始化
        if not self._analyzer:
            self.initialize({})
            logger.info("证书分析器已初始化")
        
        inner_result = {
            'plugin': self.plugin_name,
            'target': target,
            'success': False,
            'error': None
        }
        
        # 执行分析
        try:
            # 获取证书
            logger.info(f"尝试获取 {target} 的证书")
            cert_result = self._analyzer.get_certificate(target, port)
            
            if cert_result['success']:
                logger.info(f"成功获取 {target} 的证书")
                inner_result['success'] = True
                
                # 确保返回正确的证书信息格式
                if cert_result['cert']:
                    logger.debug(f"证书内容：{cert_result['cert']}")
                    
                    # 分析CDN特征
                    cdn_features = self._analyzer.analyze_certificate(cert_result['cert'])
                    logger.debug(f"CDN特征：{cdn_features}")
                    
                    # 将证书格式标准化为app.py期望的格式
                    cert_info = cert_result['cert']
                    formatted_cert = {
                        'subject': cert_info.get('subject', {}),
                        'issuer': cert_info.get('issuer', {}),
                        'sans': cert_info.get('subjectAltName', []),
                        'notBefore': cert_info.get('notBefore'),
                        'notAfter': cert_info.get('notAfter'),
                        'fingerprint': cert_info.get('fingerprint', {}),
                        'cdn_features': cdn_features
                    }
                    
                    # 为了确保结果正确，我们使用带有更清晰结构的结果
                    inner_result = {
                        'plugin': self.plugin_name,
                        'target': target,
                        'success': True,
                        'subject': formatted_cert['subject'],
                        'issuer': formatted_cert['issuer'],
                        'sans': formatted_cert['sans'],
                        'notBefore': formatted_cert['notBefore'],
                        'notAfter': formatted_cert['notAfter'],
                        'fingerprint': formatted_cert['fingerprint'],
                        'cdn_features': formatted_cert['cdn_features']
                    }
                    
                    logger.info(f"证书分析成功: {target}")
                else:
                    logger.warning(f"证书内容为空: {target}")
                    inner_result['error'] = "证书内容为空"
            else:
                inner_result['error'] = cert_result['error']
                logger.warning(f"获取证书失败: {target} - {cert_result['error']}")
        except Exception as e:
            logger.error(f"证书分析失败: {str(e)}", exc_info=True)
            inner_result['error'] = str(e)
        
        # 包装结果，确保符合app.py中的期望格式
        final_result = {
            'success': inner_result.get('success', False) and 'error' not in inner_result,
            'result': inner_result
        }
        
        logger.debug(f"证书分析最终结果: {final_result}")
        return final_result
    
    def execute(self, *args, **kwargs) -> Dict[str, Any]:
        """
        执行插件功能
        
        Args:
            *args, **kwargs: 参数
            
        Returns:
            执行结果
        """
        target = args[0] if args else kwargs.get('target')
        if not target:
            raise ValueError("目标不能为空")
            
        return self._execute(target, **kwargs)
    
    def validate(self) -> bool:
        """
        验证插件配置是否有效
        
        Returns:
            配置是否有效
        """
        port = self._config.get('port')
        if port and not isinstance(port, int):
            logger.error(f"端口配置无效: {port}")
            return False
        
        timeout = self._config.get('timeout')
        if timeout and not isinstance(timeout, int):
            logger.error(f"超时配置无效: {timeout}")
            return False
        
        logger.info("证书分析插件配置验证通过")
        return True
    
    def shutdown(self) -> None:
        """关闭证书分析插件"""
        self._analyzer = None
        logger.info("证书分析插件已关闭")
        super().shutdown() 