"""
规则更新插件 - 用于更新CDN规则
"""

from typing import Dict, Any, List, Optional, Tuple

from cdn_check.core.plugin_base import PluginBase
from cdn_check.core.rule_updater import RuleUpdater
from cdn_check.core import get_logger

# 获取日志器
logger = get_logger(__name__)

class RuleUpdatePlugin(PluginBase):
    """规则更新插件，用于更新CDN规则"""
    
    plugin_type = "updater"
    plugin_name = "rule_updater"
    plugin_description = "规则更新插件，用于更新CDN规则"
    plugin_version = "0.1.0"
    plugin_author = "CDN检测工具"
    
    def __init__(self):
        super().__init__()
        self._updater = None
        logger.info("规则更新插件初始化")
    
    def execute(self, command: str, **kwargs) -> Dict[str, Any]:
        """
        执行规则更新
        
        Args:
            command: 命令（update_from_url, update_from_text, get_rules, get_rule, delete_rule）
            **kwargs: 其他参数
                - rules_file: 规则文件路径
                - api_key: OpenAI API密钥
                - url: 规则URL（用于update_from_url）
                - text: 技术文档文本（用于update_from_text）
                - provider_name: CDN提供商名称（用于update_from_text, get_rule, delete_rule）
                - version: 版本号（用于create_version_log）
                - changes: 变更列表（用于create_version_log）
                - source: 来源（用于create_version_log）
                
        Returns:
            执行结果
        """
        # 获取参数
        rules_file = kwargs.get('rules_file') or self.get_config('rules_file')
        api_key = kwargs.get('api_key') or self.get_config('api_key')
        
        logger.info(f"执行规则更新命令: {command}")
        
        # 初始化更新器
        if not self._updater:
            try:
                self._updater = RuleUpdater(rules_file, api_key)
                logger.info(f"规则更新器初始化成功: rules_file={rules_file}")
            except Exception as e:
                logger.error(f"规则更新器初始化失败: {str(e)}", exc_info=True)
                return {
                    'plugin': self.plugin_name,
                    'command': command,
                    'success': False,
                    'message': f"规则更新器初始化失败: {str(e)}",
                    'data': None
                }
        
        result = {
            'plugin': self.plugin_name,
            'command': command,
            'success': False,
            'message': "",
            'data': None
        }
        
        try:
            if command == 'update_from_url':
                url = kwargs.get('url')
                
                if not url:
                    message = "缺少url参数"
                    logger.error(message)
                    result['message'] = message
                    return result
                
                logger.info(f"从URL更新规则: {url}")
                success, rules = self._updater.update_from_url(url)
                
                result['success'] = success
                result['message'] = f"从URL更新规则: {url}" if success else f"从URL更新规则失败: {url}"
                result['data'] = rules
            
            elif command == 'update_from_text':
                text = kwargs.get('text')
                provider_name = kwargs.get('provider_name')
                
                if not text or not provider_name:
                    message = "缺少text或provider_name参数"
                    logger.error(message)
                    result['message'] = message
                    return result
                
                logger.info(f"从文本更新规则: {provider_name}")
                success, rule = self._updater.update_from_text(text, provider_name)
                
                result['success'] = success
                result['message'] = f"从文本更新规则: {provider_name}" if success else f"从文本更新规则失败: {provider_name}"
                result['data'] = rule
            
            elif command == 'get_rules':
                rules = self._updater.get_rules()
                
                result['success'] = True
                result['message'] = f"获取规则列表: {len(rules)}条规则"
                result['data'] = rules
            
            elif command == 'get_rule':
                provider_name = kwargs.get('provider_name')
                
                if not provider_name:
                    message = "缺少provider_name参数"
                    logger.error(message)
                    result['message'] = message
                    return result
                
                rule = self._updater.get_rule(provider_name)
                
                result['success'] = bool(rule)
                result['message'] = f"获取规则: {provider_name}" if rule else f"规则不存在: {provider_name}"
                result['data'] = rule
            
            elif command == 'delete_rule':
                provider_name = kwargs.get('provider_name')
                
                if not provider_name:
                    message = "缺少provider_name参数"
                    logger.error(message)
                    result['message'] = message
                    return result
                
                success = self._updater.delete_rule(provider_name)
                
                result['success'] = success
                result['message'] = f"删除规则: {provider_name}" if success else f"删除规则失败: {provider_name}"
            
            elif command == 'create_version_log':
                version = kwargs.get('version')
                changes = kwargs.get('changes')
                source = kwargs.get('source', 'manual')
                
                if not version or not changes:
                    message = "缺少version或changes参数"
                    logger.error(message)
                    result['message'] = message
                    return result
                
                success = self._updater.create_version_log(version, changes, source)
                
                result['success'] = success
                result['message'] = f"创建版本日志: {version}" if success else f"创建版本日志失败: {version}"
            
            elif command == 'get_version_log':
                log = self._updater.get_version_log()
                
                result['success'] = True
                result['message'] = f"获取版本日志"
                result['data'] = log
            
            else:
                message = f"未知命令: {command}"
                logger.error(message)
                result['message'] = message
        except Exception as e:
            logger.error(f"执行规则更新命令失败: {command} - {str(e)}", exc_info=True)
            result['success'] = False
            result['message'] = f"执行失败: {str(e)}"
        
        logger.info(f"规则更新命令执行结果: success={result['success']}, message={result['message']}")
        return result
    
    def validate(self) -> bool:
        """
        验证插件配置是否有效
        
        Returns:
            配置是否有效
        """
        # 配置可以为空
        logger.info("规则更新插件配置验证通过")
        return True
    
    def shutdown(self) -> None:
        """关闭规则更新插件"""
        self._updater = None
        logger.info("规则更新插件已关闭")
        super().shutdown() 