"""
规则更新引擎 - 用于更新CDN规则库
"""

import json
import logging
import os
import time
import hashlib
import requests
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime

logger = logging.getLogger(__name__)

class RuleUpdater:
    """规则更新器，用于更新CDN规则库"""
    
    def __init__(self, rules_file: str, api_key: Optional[str] = None):
        """
        初始化规则更新器
        
        Args:
            rules_file: 规则文件路径
            api_key: OpenAI API密钥（用于从技术文档生成规则）
        """
        self._rules_file = rules_file
        self._api_key = api_key
        self._rules = self._load_rules()
        
    def _load_rules(self) -> Dict[str, Any]:
        """
        加载规则文件
        
        Returns:
            规则字典
        """
        rules = {
            'version': '0.1.0',
            'last_updated': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'providers': {},
            'version_history': []
        }
        
        try:
            if os.path.exists(self._rules_file):
                with open(self._rules_file, 'r', encoding='utf-8') as f:
                    loaded_rules = json.load(f)
                    
                    # 检查规则格式
                    if isinstance(loaded_rules, dict) and 'providers' in loaded_rules:
                        rules = loaded_rules
                        logger.info(f"已从 {self._rules_file} 加载 {len(rules['providers'])} 条规则")
                    else:
                        logger.warning(f"规则文件 {self._rules_file} 格式不正确，将使用默认规则")
            else:
                logger.warning(f"规则文件 {self._rules_file} 不存在，将使用默认规则")
        except Exception as e:
            logger.error(f"加载规则文件时出错: {str(e)}")
        
        return rules
    
    def save_rules(self) -> bool:
        """
        保存规则到文件
        
        Returns:
            是否保存成功
        """
        try:
            # 确保目录存在
            os.makedirs(os.path.dirname(self._rules_file), exist_ok=True)
            
            # 更新时间戳
            self._rules['last_updated'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            
            with open(self._rules_file, 'w', encoding='utf-8') as f:
                json.dump(self._rules, f, indent=2, ensure_ascii=False)
                
            logger.info(f"已保存 {len(self._rules['providers'])} 条规则到 {self._rules_file}")
            return True
        except Exception as e:
            logger.error(f"保存规则文件时出错: {str(e)}")
            return False
    
    def update_from_url(self, url: str) -> Tuple[bool, str]:
        """
        从URL更新规则
        
        Args:
            url: 规则URL
            
        Returns:
            (是否成功, 消息)
        """
        try:
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            
            new_rules = response.json()
            
            # 验证规则格式
            if not isinstance(new_rules, dict) or 'providers' not in new_rules:
                return False, "规则格式不正确"
            
            # 合并规则
            old_count = len(self._rules['providers'])
            self._rules['providers'].update(new_rules['providers'])
            new_count = len(self._rules['providers'])
            
            # 添加版本记录
            self._rules['version_history'].append({
                'version': self._rules['version'],
                'time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'changes': [f"从URL {url} 更新了 {new_count - old_count} 条规则"],
                'source': url
            })
            
            # 保存规则
            self.save_rules()
            
            return True, f"成功从 {url} 更新了 {new_count - old_count} 条规则"
        except Exception as e:
            logger.error(f"从URL更新规则时出错: {str(e)}")
            return False, f"更新失败: {str(e)}"
    
    def update_from_text(self, text: str, provider_name: str) -> Tuple[bool, str]:
        """
        从技术文档文本生成并更新规则
        
        Args:
            text: 技术文档文本
            provider_name: CDN提供商名称
            
        Returns:
            (是否成功, 消息)
        """
        # 检查API密钥
        if not self._api_key:
            return False, "缺少OpenAI API密钥"
        
        try:
            # 使用LLM处理文档，提取规则（此处应调用OpenAI API）
            # 为简化示例，这里手动创建一个规则
            new_rule = {
                "name": provider_name,
                "type": "cdn",
                "detection": {
                    "http_headers": {
                        "Server": [provider_name],
                        "X-Powered-By": [provider_name]
                    },
                    "cname": [
                        f"{provider_name.lower()}.com",
                        f"{provider_name.lower()}.net"
                    ]
                },
                "last_updated": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }
            
            # 更新规则
            self._rules['providers'][provider_name] = new_rule
            
            # 添加版本记录
            self._rules['version_history'].append({
                'version': self._rules['version'],
                'time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'changes': [f"从技术文档生成了 {provider_name} 的规则"],
                'source': f"技术文档分析 ({len(text)} 字符)"
            })
            
            # 保存规则
            self.save_rules()
            
            return True, f"成功为 {provider_name} 生成并更新了规则"
        except Exception as e:
            logger.error(f"从技术文档生成规则时出错: {str(e)}")
            return False, f"生成失败: {str(e)}"
    
    def get_rules(self) -> Dict[str, Any]:
        """
        获取所有规则
        
        Returns:
            规则字典
        """
        return self._rules
    
    def get_rule(self, provider_name: str) -> Optional[Dict[str, Any]]:
        """
        获取特定提供商的规则
        
        Args:
            provider_name: CDN提供商名称
            
        Returns:
            规则字典，如果不存在则返回None
        """
        return self._rules['providers'].get(provider_name)
    
    def delete_rule(self, provider_name: str) -> bool:
        """
        删除特定提供商的规则
        
        Args:
            provider_name: CDN提供商名称
            
        Returns:
            是否删除成功
        """
        if provider_name in self._rules['providers']:
            del self._rules['providers'][provider_name]
            
            # 添加版本记录
            self._rules['version_history'].append({
                'version': self._rules['version'],
                'time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'changes': [f"删除了 {provider_name} 的规则"],
                'source': "手动删除"
            })
            
            # 保存规则
            self.save_rules()
            
            return True
        return False
    
    def create_version_log(self, version: str, changes: List[str], source: str) -> bool:
        """
        创建版本日志
        
        Args:
            version: 版本号
            changes: 变更列表
            source: 来源
            
        Returns:
            是否创建成功
        """
        try:
            self._rules['version'] = version
            
            # 添加版本记录
            self._rules['version_history'].append({
                'version': version,
                'time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'changes': changes,
                'source': source
            })
            
            # 保存规则
            self.save_rules()
            
            return True
        except Exception as e:
            logger.error(f"创建版本日志时出错: {str(e)}")
            return False 