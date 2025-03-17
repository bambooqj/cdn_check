"""
CDN检测插件 - 用于检测目标是否使用CDN
"""

from typing import Dict, Any, List, Optional
import os
import logging
import json

from cdn_check.core.plugin_base import PluginBase
from cdn_check.core.cdn_detector import CDNDetector
from cdn_check.core import get_logger

# 获取日志器
logger = logging.getLogger(__name__)

class CDNPlugin(PluginBase):
    """CDN检测插件，用于检测目标是否使用CDN"""
    
    plugin_type = "detector"
    plugin_name = "cdn_detector"
    plugin_description = "CDN检测插件，用于检测目标是否使用CDN"
    plugin_version = "0.1.0"
    plugin_author = "CDN检测工具"
    
    def __init__(self):
        super().__init__()
        
        # 初始化CDN检测器
        rules_file = self.get_config('rules_file')
        logger.info(f"初始化CDN检测器，规则文件: {rules_file}")
        self._detector = CDNDetector(rules_file)
        self.last_result = None  # 存储最后一次检测结果
    
    def execute(self, data: Dict[str, Any], **kwargs) -> Dict[str, Any]:
        """
        执行CDN检测
        
        Args:
            data: 包含检测所需数据的字典，应包含以下字段：
                - domain: 域名
                - ips: IP地址列表
                - cname_chain: CNAME链
                - http_headers: HTTP头
                - cert: 证书信息
            **kwargs: 其他参数
                
        Returns:
            CDN检测结果
        """
        target = data.get('domain', '')
        logger.info(f"执行CDN检测: {target}")
        
        result = {
            'plugin': self.plugin_name,
            'target': target,
            'success': True,
            'result': None
        }
        
        # 执行检测
        try:
            detection_result = self._detector.detect(data)
            result['result'] = detection_result
            logger.info(f"CDN检测结果: {detection_result.get('is_cdn', False)}")
            
            # 保存检测结果
            self.last_result = detection_result
        except Exception as e:
            logger.error(f"CDN检测失败: {str(e)}", exc_info=True)
            result['success'] = False
            result['error'] = str(e)
        
        return result
    
    def add_rule(self, rule: Dict[str, Any]) -> bool:
        """
        添加CDN规则
        
        Args:
            rule: CDN规则字典
            
        Returns:
            是否添加成功
        """
        logger.info(f"添加CDN规则: {rule.get('name', '')}")
        return self._detector.add_rule(rule)
    
    def get_rules(self) -> List[Dict[str, Any]]:
        """
        获取所有CDN规则
        
        Returns:
            CDN规则列表
        """
        logger.debug("获取所有CDN规则")
        return self._detector.get_rules()
    
    def save_rules(self, file_path: Optional[str] = None) -> bool:
        """
        保存CDN规则到文件
        
        Args:
            file_path: 文件路径，如果为None则使用配置中的路径
            
        Returns:
            是否保存成功
        """
        if file_path is None:
            file_path = self.get_config('rules_file')
            
        if not file_path:
            logger.error("保存规则失败：未指定文件路径")
            return False
            
        logger.info(f"保存CDN规则到文件: {file_path}")
        return self._detector.save_rules(file_path)
    
    def validate(self) -> bool:
        """
        验证插件配置是否有效
        
        Returns:
            配置是否有效
        """
        rules_file = self.get_config('rules_file')
        if rules_file and not os.path.exists(rules_file):
            logger.error(f"规则文件不存在: {rules_file}")
            return False
        
        logger.info("CDN检测插件配置验证通过")
        return True
    
    def provide_feedback(self, is_correct: bool, actual_provider: Optional[str] = None) -> None:
        """
        提供检测结果的反馈，用于自学习
        
        Args:
            is_correct: 检测结果是否正确
            actual_provider: 实际的CDN提供商（如果已知）
        """
        if self.last_result is None:
            logger.warning("无法提供反馈，没有最近的检测结果")
            return
            
        # 1. 通过检测器内部机制提供反馈
        self._detector.provide_feedback(self.last_result, is_correct, actual_provider)
        
        # 2. 尝试将反馈保存到数据库
        try:
            from cdn_check.core.db_manager import DBManager
            db = DBManager()
            
            # 尝试查找最近的会话
            latest_session = None
            # 此处逻辑简单，实际情况下可能需要更复杂的匹配方法
            if self.last_result and 'target' in self.last_result:
                target = self.last_result.get('target', None)
                
                if target:
                    latest_session = db.get_latest_session_for_target(target)
                    logger.info(f"找到目标 {target} 的最新会话: {latest_session['id'] if latest_session else 'None'}")
            
            # 如果找到了匹配的会话，更新反馈
            if latest_session:
                success = db.save_feedback(latest_session['id'], is_correct, actual_provider)
                if success:
                    logger.info(f"已保存反馈到数据库，会话ID: {latest_session['id']}")
                else:
                    logger.warning(f"保存反馈到数据库失败，会话ID: {latest_session['id']}")
            else:
                logger.warning("未找到匹配的检测会话，无法保存反馈到数据库")
        except Exception as e:
            logger.error(f"保存反馈到数据库时出错: {str(e)}", exc_info=True)
        
        logger.info(f"已提供检测反馈: 正确={is_correct}, 实际提供商={actual_provider}") 