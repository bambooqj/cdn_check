import os
import sqlite3
import json
import logging
import datetime
from typing import Dict, Any, List, Optional, Tuple

logger = logging.getLogger(__name__)

class DBManager:
    """
    数据库管理器，用于保存和查询CDN检测数据
    """
    
    _instance = None
    
    def __new__(cls, db_path: Optional[str] = None):
        """实现单例模式"""
        if cls._instance is None:
            cls._instance = super(DBManager, cls).__new__(cls)
            cls._instance._initialized = False
        return cls._instance
    
    def __init__(self, db_path: Optional[str] = None):
        """
        初始化数据库管理器
        
        Args:
            db_path: 数据库文件路径，如果为None则使用默认路径
        """
        # 避免重复初始化
        if hasattr(self, '_initialized') and self._initialized:
            return
        
        # 初始化数据库路径
        if db_path is None:
            # 使用默认路径
            base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
            data_dir = os.path.join(base_dir, "data")
            os.makedirs(data_dir, exist_ok=True)
            db_path = os.path.join(data_dir, "cdn_detection.db")
        
        self._db_path = db_path
        self._conn = None
        self._create_tables()
        self._initialized = True
        
        logger.info(f"数据库管理器初始化完成，数据库路径: {self._db_path}")
    
    def _connect(self) -> sqlite3.Connection:
        """
        连接到数据库
        
        Returns:
            数据库连接对象
        """
        if self._conn is None:
            try:
                self._conn = sqlite3.connect(self._db_path)
                self._conn.row_factory = sqlite3.Row  # 启用行工厂，使查询结果可通过列名访问
                logger.debug(f"已连接到数据库: {self._db_path}")
            except sqlite3.Error as e:
                logger.error(f"连接数据库失败: {str(e)}")
                raise
        return self._conn
    
    def _close(self) -> None:
        """关闭数据库连接"""
        if self._conn is not None:
            try:
                self._conn.close()
                self._conn = None
                logger.debug("已关闭数据库连接")
            except sqlite3.Error as e:
                logger.error(f"关闭数据库连接失败: {str(e)}")
    
    def _create_tables(self) -> None:
        """创建必要的数据库表"""
        global conn
        try:
            conn = self._connect()
            cursor = conn.cursor()
            
            # 创建检测会话表
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS detection_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                is_cdn BOOLEAN,
                cdn_provider TEXT,
                confidence REAL,
                user_feedback BOOLEAN,
                actual_provider TEXT,
                feedback_timestamp TEXT
            )
            ''')
            
            # 创建检测指标表
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS detection_indicators (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id INTEGER NOT NULL,
                indicator TEXT NOT NULL,
                feature_type TEXT NOT NULL,
                weight REAL,
                contributed_to_result BOOLEAN,
                FOREIGN KEY (session_id) REFERENCES detection_sessions (id)
            )
            ''')
            
            # 创建原始数据表
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS raw_data (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id INTEGER NOT NULL,
                data_type TEXT NOT NULL,
                data_json TEXT NOT NULL,
                FOREIGN KEY (session_id) REFERENCES detection_sessions (id)
            )
            ''')
            
            # 创建IP信息表
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS ip_info (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id INTEGER NOT NULL,
                ip TEXT NOT NULL,
                asn TEXT,
                organization TEXT,
                country TEXT,
                city TEXT,
                is_cdn_ip BOOLEAN,
                cdn_provider TEXT,
                FOREIGN KEY (session_id) REFERENCES detection_sessions (id)
            )
            ''')
            
            # 创建模型训练记录表
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS model_training (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                model_type TEXT NOT NULL,
                parameters TEXT,
                accuracy REAL,
                f1_score REAL,
                precision_score REAL,
                recall_score REAL,
                training_data_count INTEGER
            )
            ''')
            
            conn.commit()
            logger.info("数据库表创建完成")
        except sqlite3.Error as e:
            logger.error(f"创建数据库表失败: {str(e)}")
            if conn:
                conn.rollback()
    
    def save_detection_result(self, 
                              target: str, 
                              result: Dict[str, Any]) -> int:
        """
        保存检测结果到数据库
        
        Args:
            target: 检测目标（域名或IP）
            result: 检测结果字典
            
        Returns:
            会话ID
        """
        try:
            conn = self._connect()
            cursor = conn.cursor()
            
            # 1. 保存检测会话
            is_cdn = result.get('is_cdn', False)
            
            # 处理cdn_provider可能的不同类型
            provider = result.get('cdn_provider')
            if provider is None:
                cdn_provider = ''
            elif isinstance(provider, list):
                cdn_provider = ','.join(provider)
            else:
                cdn_provider = str(provider)
                
            confidence = result.get('confidence', 0.0)
            timestamp = datetime.datetime.now().isoformat()
            
            cursor.execute('''
            INSERT INTO detection_sessions (
                target, timestamp, is_cdn, cdn_provider, confidence
            ) VALUES (?, ?, ?, ?, ?)
            ''', (target, timestamp, is_cdn, cdn_provider, confidence))
            
            session_id = cursor.lastrowid
            
            # 2. 保存检测指标
            indicators = result.get('indicators', [])
            if indicators:
                for indicator in indicators:
                    # 解析指标类型
                    feature_type = 'generic'
                    if "HTTP头" in indicator or "Server头" in indicator:
                        feature_type = 'http_header'
                    elif "缓存控制头部" in indicator:
                        feature_type = 'cache_header'
                    elif "IP匹配" in indicator:
                        feature_type = 'ip_range'
                    elif "多个A记录" in indicator:
                        feature_type = 'ip_diversity'
                    elif "IP地理分布" in indicator:
                        feature_type = 'geo_diversity'
                    elif "CNAME匹配" in indicator:
                        feature_type = 'cname'
                    elif "证书" in indicator:
                        feature_type = 'cert'
                    elif "TTL" in indicator:
                        feature_type = 'ttl'
                    
                    cursor.execute('''
                    INSERT INTO detection_indicators (
                        session_id, indicator, feature_type, weight, contributed_to_result
                    ) VALUES (?, ?, ?, ?, ?)
                    ''', (session_id, indicator, feature_type, 0.0, True))
            
            # 3. 保存原始数据
            if 'details' in result:
                details = result['details']
                
                # DNS数据
                if 'dns' in details:
                    cursor.execute('''
                    INSERT INTO raw_data (
                        session_id, data_type, data_json
                    ) VALUES (?, ?, ?)
                    ''', (session_id, 'dns', json.dumps(details['dns'])))
                
                # HTTP数据
                if 'http' in details:
                    cursor.execute('''
                    INSERT INTO raw_data (
                        session_id, data_type, data_json
                    ) VALUES (?, ?, ?)
                    ''', (session_id, 'http', json.dumps(details['http'])))
                
                # 证书数据
                if 'cert' in details:
                    cursor.execute('''
                    INSERT INTO raw_data (
                        session_id, data_type, data_json
                    ) VALUES (?, ?, ?)
                    ''', (session_id, 'cert', json.dumps(details['cert'])))
                
                # IP数据
                if 'ip' in details:
                    ip_data = details['ip']
                    for ip, info in ip_data.items():
                        if isinstance(info, dict):
                            organization = info.get('organization', info.get('org', ''))
                            country = info.get('country', '')
                            if isinstance(country, dict):
                                country = country.get('name', '')
                            
                            city = info.get('city', '')
                            if isinstance(city, dict):
                                city = city.get('name', '')
                            
                            asn = info.get('asn', '')
                            if isinstance(asn, dict):
                                asn = str(asn.get('asn', ''))
                            
                            is_cdn_ip = info.get('is_cdn', info.get('is_cdn_ip', False))
                            cdn_provider_ip = info.get('cdn_provider', '')
                            
                            cursor.execute('''
                            INSERT INTO ip_info (
                                session_id, ip, asn, organization, country, 
                                city, is_cdn_ip, cdn_provider
                            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                            ''', (
                                session_id, ip, asn, organization, country, 
                                city, is_cdn_ip, cdn_provider_ip
                            ))
            
            conn.commit()
            logger.info(f"成功保存检测结果到数据库，会话ID: {session_id}")
            return session_id
            
        except sqlite3.Error as e:
            logger.error(f"保存检测结果失败: {str(e)}")
            if conn:
                conn.rollback()
            return -1
    
    def save_feedback(self, 
                      session_id: int, 
                      is_correct: bool, 
                      actual_provider: Optional[str] = None) -> bool:
        """
        保存用户反馈信息
        
        Args:
            session_id: 检测会话ID
            is_correct: 检测结果是否正确
            actual_provider: 实际的CDN提供商（如果已知）
            
        Returns:
            是否成功保存
        """
        try:
            conn = self._connect()
            cursor = conn.cursor()
            
            # 先检查会话是否存在
            cursor.execute('SELECT id FROM detection_sessions WHERE id = ?', (session_id,))
            if not cursor.fetchone():
                logger.error(f"保存反馈信息失败: 会话ID {session_id} 不存在")
                return False
            
            # 确保布尔值处理正确
            if not isinstance(is_correct, bool):
                is_correct = bool(is_correct)
            
            timestamp = datetime.datetime.now().isoformat()
            
            logger.debug(f"保存反馈 - 会话ID: {session_id}, 正确: {is_correct}, 提供商: {actual_provider}")
            
            cursor.execute('''
            UPDATE detection_sessions 
            SET user_feedback = ?, actual_provider = ?, feedback_timestamp = ? 
            WHERE id = ?
            ''', (is_correct, actual_provider, timestamp, session_id))
            
            # 检查更新是否成功
            if cursor.rowcount == 0:
                logger.warning(f"没有记录被更新，会话ID: {session_id}")
                conn.rollback()
                return False
            
            conn.commit()
            logger.info(f"成功保存反馈信息，会话ID: {session_id}")
            return True
            
        except sqlite3.Error as e:
            logger.error(f"保存反馈信息失败: {str(e)}")
            if 'conn' in locals() and conn:
                conn.rollback()
            return False
    
    def save_model_training(self, 
                           model_type: str, 
                           parameters: Dict[str, Any],
                           metrics: Dict[str, float],
                           training_data_count: int) -> int:
        """
        保存模型训练记录
        
        Args:
            model_type: 模型类型
            parameters: 模型参数
            metrics: 模型评估指标
            training_data_count: 训练数据数量
            
        Returns:
            记录ID
        """
        try:
            conn = self._connect()
            cursor = conn.cursor()
            
            timestamp = datetime.datetime.now().isoformat()
            
            cursor.execute('''
            INSERT INTO model_training (
                timestamp, model_type, parameters, accuracy, f1_score,
                precision_score, recall_score, training_data_count
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                timestamp, 
                model_type, 
                json.dumps(parameters), 
                metrics.get('accuracy', 0.0),
                metrics.get('f1_score', 0.0),
                metrics.get('precision', 0.0),
                metrics.get('recall', 0.0),
                training_data_count
            ))
            
            record_id = cursor.lastrowid
            conn.commit()
            logger.info(f"成功保存模型训练记录，ID: {record_id}")
            return record_id
            
        except sqlite3.Error as e:
            logger.error(f"保存模型训练记录失败: {str(e)}")
            if conn:
                conn.rollback()
            return -1
    
    def get_detection_session(self, session_id: int) -> Optional[Dict[str, Any]]:
        """
        获取检测会话信息
        
        Args:
            session_id: 会话ID
            
        Returns:
            会话信息字典，如果不存在则返回None
        """
        try:
            conn = self._connect()
            cursor = conn.cursor()
            
            cursor.execute('''
            SELECT * FROM detection_sessions WHERE id = ?
            ''', (session_id,))
            
            row = cursor.fetchone()
            if row:
                return dict(row)
            return None
            
        except sqlite3.Error as e:
            logger.error(f"获取检测会话失败: {str(e)}")
            return None
    
    def get_latest_session_for_target(self, target: str) -> Optional[Dict[str, Any]]:
        """
        获取目标的最新检测会话
        
        Args:
            target: 检测目标
            
        Returns:
            最新会话信息字典，如果不存在则返回None
        """
        try:
            conn = self._connect()
            cursor = conn.cursor()
            
            cursor.execute('''
            SELECT * FROM detection_sessions 
            WHERE target = ? 
            ORDER BY timestamp DESC LIMIT 1
            ''', (target,))
            
            row = cursor.fetchone()
            if row:
                return dict(row)
            return None
            
        except sqlite3.Error as e:
            logger.error(f"获取最新检测会话失败: {str(e)}")
            return None
    
    def get_session_indicators(self, session_id: int) -> List[Dict[str, Any]]:
        """
        获取会话的检测指标
        
        Args:
            session_id: 会话ID
            
        Returns:
            检测指标列表
        """
        try:
            conn = self._connect()
            cursor = conn.cursor()
            
            cursor.execute('''
            SELECT * FROM detection_indicators WHERE session_id = ?
            ''', (session_id,))
            
            rows = cursor.fetchall()
            return [dict(row) for row in rows]
            
        except sqlite3.Error as e:
            logger.error(f"获取检测指标失败: {str(e)}")
            return []
    
    def get_session_raw_data(self, session_id: int, data_type: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        获取会话的原始数据
        
        Args:
            session_id: 会话ID
            data_type: 数据类型，如果为None则返回所有类型
            
        Returns:
            原始数据列表
        """
        try:
            conn = self._connect()
            cursor = conn.cursor()
            
            if data_type:
                cursor.execute('''
                SELECT * FROM raw_data 
                WHERE session_id = ? AND data_type = ?
                ''', (session_id, data_type))
            else:
                cursor.execute('''
                SELECT * FROM raw_data WHERE session_id = ?
                ''', (session_id,))
            
            rows = cursor.fetchall()
            result = []
            for row in rows:
                data = dict(row)
                try:
                    data['data'] = json.loads(data['data_json'])
                    del data['data_json']
                except:
                    pass
                result.append(data)
            return result
            
        except sqlite3.Error as e:
            logger.error(f"获取原始数据失败: {str(e)}")
            return []
    
    def get_session_ip_info(self, session_id: int) -> List[Dict[str, Any]]:
        """
        获取会话的IP信息
        
        Args:
            session_id: 会话ID
            
        Returns:
            IP信息列表
        """
        try:
            conn = self._connect()
            cursor = conn.cursor()
            
            cursor.execute('''
            SELECT * FROM ip_info WHERE session_id = ?
            ''', (session_id,))
            
            rows = cursor.fetchall()
            return [dict(row) for row in rows]
            
        except sqlite3.Error as e:
            logger.error(f"获取IP信息失败: {str(e)}")
            return []
    
    def get_all_sessions(self, 
                        limit: int = 1000, 
                        offset: int = 0, 
                        with_feedback_only: bool = False) -> List[Dict[str, Any]]:
        """
        获取所有检测会话
        
        Args:
            limit: 返回记录数量限制
            offset: 起始偏移量
            with_feedback_only: 是否只返回有反馈的会话
            
        Returns:
            会话信息列表
        """
        try:
            conn = self._connect()
            cursor = conn.cursor()
            
            if with_feedback_only:
                cursor.execute('''
                SELECT * FROM detection_sessions 
                WHERE user_feedback IS NOT NULL
                ORDER BY timestamp DESC LIMIT ? OFFSET ?
                ''', (limit, offset))
            else:
                cursor.execute('''
                SELECT * FROM detection_sessions 
                ORDER BY timestamp DESC LIMIT ? OFFSET ?
                ''', (limit, offset))
            
            rows = cursor.fetchall()
            return [dict(row) for row in rows]
            
        except sqlite3.Error as e:
            logger.error(f"获取检测会话列表失败: {str(e)}")
            return []
    
    def get_feature_accuracy(self) -> Dict[str, Dict[str, Any]]:
        """
        获取各个特征的准确率统计
        
        Returns:
            特征准确率统计字典
        """
        try:
            conn = self._connect()
            cursor = conn.cursor()
            
            # 查询带反馈的会话中各个特征类型的命中统计
            cursor.execute('''
            SELECT 
                i.feature_type, 
                COUNT(*) as total,
                SUM(CASE WHEN s.user_feedback = 1 THEN 1 ELSE 0 END) as correct
            FROM detection_indicators i
            JOIN detection_sessions s ON i.session_id = s.id
            WHERE s.user_feedback IS NOT NULL
            GROUP BY i.feature_type
            ''')
            
            rows = cursor.fetchall()
            result = {}
            
            for row in rows:
                feature_type = row['feature_type']
                total = row['total']
                correct = row['correct']
                accuracy = correct / total if total > 0 else 0
                
                result[feature_type] = {
                    'total': total,
                    'correct': correct,
                    'accuracy': accuracy
                }
            
            return result
            
        except sqlite3.Error as e:
            logger.error(f"获取特征准确率统计失败: {str(e)}")
            return {}
    
    def get_training_data(self, 
                         limit: int = 10000, 
                         with_feedback_only: bool = True) -> Tuple[List[Dict[str, Any]], List[bool]]:
        """
        获取用于机器学习的训练数据
        
        Args:
            limit: 返回记录数量限制
            with_feedback_only: 是否只返回有反馈的会话
            
        Returns:
            (特征数据列表, 标签列表)
        """
        try:
            conn = self._connect()
            cursor = conn.cursor()
            
            # 获取会话数据
            if with_feedback_only:
                cursor.execute('''
                SELECT id, is_cdn, user_feedback 
                FROM detection_sessions 
                WHERE user_feedback IS NOT NULL
                LIMIT ?
                ''', (limit,))
            else:
                cursor.execute('''
                SELECT id, is_cdn 
                FROM detection_sessions 
                LIMIT ?
                ''', (limit,))
            
            session_rows = cursor.fetchall()
            features = []
            labels = []
            
            for session in session_rows:
                session_id = session['id']
                # 标签：如果有用户反馈，使用反馈的正确性；否则使用检测结果
                if with_feedback_only:
                    label = bool(session['user_feedback'])
                else:
                    label = bool(session['is_cdn'])
                
                # 获取会话的特征数据
                feature_data = self._extract_session_features(session_id)
                if feature_data:
                    features.append(feature_data)
                    labels.append(label)
            
            return features, labels
            
        except sqlite3.Error as e:
            logger.error(f"获取训练数据失败: {str(e)}")
            return [], []
    
    def _extract_session_features(self, session_id: int) -> Optional[Dict[str, Any]]:
        """
        从会话数据中提取特征
        
        Args:
            session_id: 会话ID
            
        Returns:
            特征数据字典
        """
        try:
            conn = self._connect()
            cursor = conn.cursor()
            
            # 基本会话信息
            cursor.execute('''
            SELECT target, is_cdn, cdn_provider, confidence 
            FROM detection_sessions WHERE id = ?
            ''', (session_id,))
            
            session = cursor.fetchone()
            if not session:
                return None
                
            # 提取特征
            features = {
                'session_id': session_id,
                'target': session['target'],
                # 初始化特征计数器
                'ip_range_count': 0,
                'ip_diversity_count': 0,
                'geo_diversity_count': 0,
                'http_header_count': 0,
                'cache_header_count': 0,
                'cname_count': 0,
                'cert_count': 0,
                'ttl_count': 0,
                'total_ip_count': 0,
                'cdn_ip_ratio': 0.0,
                'different_countries_count': 0
            }
            
            # 统计指标类型
            cursor.execute('''
            SELECT feature_type, COUNT(*) as count 
            FROM detection_indicators 
            WHERE session_id = ? 
            GROUP BY feature_type
            ''', (session_id,))
            
            for row in cursor.fetchall():
                feature_type = row['feature_type']
                count = row['count']
                if feature_type in features:
                    features[f"{feature_type}_count"] = count
            
            # 获取IP信息
            cursor.execute('''
            SELECT ip, is_cdn_ip, country 
            FROM ip_info 
            WHERE session_id = ?
            ''', (session_id,))
            
            ip_rows = cursor.fetchall()
            if ip_rows:
                features['total_ip_count'] = len(ip_rows)
                
                cdn_ip_count = sum(1 for row in ip_rows if row['is_cdn_ip'])
                features['cdn_ip_ratio'] = cdn_ip_count / len(ip_rows) if len(ip_rows) > 0 else 0
                
                countries = set(row['country'] for row in ip_rows if row['country'])
                features['different_countries_count'] = len(countries)
            
            return features
            
        except sqlite3.Error as e:
            logger.error(f"提取会话特征失败: {str(e)}")
            return None
    
    def __del__(self):
        """析构函数，确保关闭数据库连接"""
        self._close() 