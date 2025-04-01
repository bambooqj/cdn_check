# CDN检测工具

## 概述
CDN检测工具是一个插件化的网络情报分析框架，主要用于检测目标域名是否使用CDN服务。通过多维度特征分析（IP、HTTP头、DNS、证书），实现基础的CDN检测功能。

## 特性
- **多维度检测**：综合分析IP、HTTP头、CNAME、证书等多个维度的特征。
- **插件化架构**：支持扩展多种插件，实现功能模块化。
- **批量检测**：支持单个目标和批量目标的检测。
- **丰富的输出**：支持控制台彩色输出和JSON格式导出。
- **高度可配置**：通过配置文件灵活调整检测参数和日志设置。

---

## 安

### 系统要求
- Python 3.8+
- Windows/Linux/macOS

### 安装步骤

```bash
# 克隆项目
git clone https://github.com/bambooqj/cdn_check.git
cd cdn-checker

# 安装依赖
pip install -r requirements.txt
```

## 使用方法

### 检测单个域名

```bash
# 基本检测
python -m cdn_check.cli check example.com

# 使用简化输出（不显示详细信息）
python -m cdn_check.cli check example.com --simple

# 指定输出格式为JSON
python -m cdn_check.cli check example.com --format json

# 保存结果到文件
python -m cdn_check.cli check example.com --output results.txt

# 指定使用特定插件
python -m cdn_check.cli check example.com --plugin cdn_detector
```

### 批量检测

```bash
# 批量检测（从文件读取目标）
python -m cdn_check.cli batch targets.txt

# 设置并发数
python -m cdn_check.cli batch targets.txt --concurrency 20

# 输出结果到CSV文件
python -m cdn_check.cli batch targets.txt --output results.csv
```

### 查看历史数据和统计信息

```bash
# 查看历史检测记录
python -m cdn_check.cli history

# 查看所有历史记录
python -m cdn_check.cli history --all

# 只查看有用户反馈的记录
python -m cdn_check.cli history --with-feedback

# 查看特定检测会话的详细信息
python -m cdn_check.cli detail 123

# 查看检测统计信息
python -m cdn_check.cli stats

# 导出历史数据
python -m cdn_check.cli export data.csv
python -m cdn_check.cli export data.json --format json
python -m cdn_check.cli export data.csv --with-feedback-only
```

### 其他命令

```bash
# 查看所有已加载的插件
python -m cdn_check.cli plugins

# 测试单个插件功能
python -m cdn_check.cli test_plugin dns_resolver example.com
python -m cdn_check.cli test_plugin http_requester https://example.com
python -m cdn_check.cli test_plugin ip_analyzer 104.21.48.1

# 提供检测结果反馈（用于自学习）
python -m cdn_check.cli feedback --correct
python -m cdn_check.cli feedback --incorrect --provider Cloudflare
```

## 配置文件

配置文件（默认为`config.json`）用于设置全局参数、插件配置和日志设置。

### 配置示例

```json
{
  "logging": {
    "level": "info",
    "file": "log/cdn_check.log",
    "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
  },
  "cdn_detection_weights": {
    "ip_range": 0.3,
    "ip_diversity": {
      "3-5": 0.1,
      "6-10": 0.3,
      "10+": 0.5
    },
    "geo_diversity": 0.3,
    "http_header": 0.5,
    "cache_header": 0.2,
    "cname": 0.4,
    "cert": 0.3,
    "ttl": 0.2,
    "dimension_bonus": {
      "2": 1.1,
      "3+": 1.1
    },
    "http_multi_bonus": 0.3
  },
  "httpheader_check": [
    {
      "name": "Server",
      "pattern": "cloudflare",
      "cdn": "Cloudflare",
      "match_type": "regex"
    }
  ],
  "dns": {
    "timeout": 5,
    "nameservers": ["8.8.8.8", "1.1.1.1"]
  },
  "http": {
    "timeout": 10,
    "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "verify_ssl": true
  }
}
```

## 数据库与机器学习支持

CDN检测工具使用SQLite数据库保存检测数据，为机器学习提供数据支持。数据库存储位置默认为`data/cdn_detection.db`。

### 数据库结构

数据库包含以下主要表：

1. **detection_sessions**：保存检测会话信息，包括目标、时间、检测结果等
2. **detection_indicators**：保存检测指标信息，如匹配到的规则、特征类型等
3. **raw_data**：保存原始检测数据，如DNS解析、HTTP头部等
4. **ip_info**：保存IP信息，如地理位置、ASN等
5. **model_training**：保存模型训练记录，如训练时间、参数、评估指标等

### 用于机器学习的功能

1. **特征提取**：`DBManager.get_training_data()`方法可提取用于机器学习的特征数据
2. **特征统计**：`DBManager.get_feature_accuracy()`方法可统计各特征的准确率
3. **数据导出**：`export`命令支持将数据导出为CSV或JSON格式，便于在外部工具中分析
4. **模型记录**：支持记录模型训练参数和评估结果，便于模型比较和选择

### 机器学习流程示例

```python
from cdn_check.core.db_manager import DBManager

# 获取训练数据
db = DBManager()
features, labels = db.get_training_data(limit=5000, with_feedback_only=True)

# 准备训练和测试集
from sklearn.model_selection import train_test_split
X_train, X_test, y_train, y_test = train_test_split(features, labels, test_size=0.2)

# 训练模型
from sklearn.ensemble import RandomForestClassifier
model = RandomForestClassifier()
model.fit(X_train, y_train)

# 评估模型
y_pred = model.predict(X_test)
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score
metrics = {
    'accuracy': accuracy_score(y_test, y_pred),
    'f1_score': f1_score(y_test, y_pred),
    'precision': precision_score(y_test, y_pred),
    'recall': recall_score(y_test, y_pred)
}

# 保存模型训练记录
db.save_model_training(
    model_type='RandomForest',
    parameters={'n_estimators': 100, 'max_depth': 10},
    metrics=metrics,
    training_data_count=len(X_train)
)
```

## 自学习模块

CDN检测工具具有自学习能力，能够根据用户反馈和历史检测结果自动调整特征权重，提高检测准确率。

### 自学习特性

1. **动态权重调整**：根据历史检测准确率，自动调整不同检测特征的权重
2. **用户反馈系统**：允许用户对检测结果提供正确性反馈
3. **特征准确率跟踪**：记录每种特征的命中率和准确率
4. **维度平衡**：自动平衡不同维度（IP、HTTP、DNS、证书）的检测权重

### 使用方法

#### 提供反馈

在执行检测命令后，可以使用以下命令提供反馈：

```bash
python -m cdn_check.cli feedback --correct  # 检测结果正确
python -m cdn_check.cli feedback --incorrect --provider Cloudflare  # 检测结果不正确，实际是Cloudflare
```

#### 权重配置

可以在`config.json`中配置初始特征权重：

```json
"cdn_detection_weights": {
  "ip_range": 0.3,
  "ip_diversity": {
    "3-5": 0.1,
    "6-10": 0.3,
    "10+": 0.5
  },
  "geo_diversity": 0.3,
  "http_header": 0.5,
  "cache_header": 0.2,
  "cname": 0.4,
  "cert": 0.3,
  "ttl": 0.2,
  "dimension_bonus": {
    "2": 1.1,
    "3+": 1.1
  },
  "http_multi_bonus": 0.3
}
```

## 插件系统

CDN检测工具采用插件化架构，各功能模块以插件形式实现，方便扩展和维护。

### 内置插件

- **cdn_detector**：核心CDN检测逻辑，综合分析多维度特征
- **dns_plugin**：DNS解析插件，获取域名的A记录、CNAME链等信息
- **http_plugin**：HTTP请求插件，获取HTTP头部信息
- **cert_plugin**：证书分析插件，获取和分析HTTPS证书信息
- **ip_plugin**：IP分析插件，获取IP的地理位置、ASN信息等
- **rule_plugin**：规则匹配插件，支持自定义规则检测

### 开发自定义插件

自定义插件需继承`PluginBase`类并实现相应接口：

```python
from cdn_check.core.plugin_base import PluginBase

class CustomPlugin(PluginBase):
    plugin_name = "custom_plugin"
    plugin_description = "自定义插件示例"
    plugin_version = "0.1.0"
    
    def __init__(self):
        super().__init__()
        # 初始化代码
        
    def execute(self, data):
        # 实现插件逻辑
        return {
            "plugin": self.plugin_name,
            "success": True,
            "result": {}
        }
```

## 输出格式

### 控制台输出（默认）

检测结果在控制台以彩色格式显示，包含：
- 检测结果摘要（是否使用CDN、提供商、置信度）
- 匹配到的CDN特征指标
- 原始检测数据（DNS、HTTP、IP、证书信息）

### JSON输出

使用`--format json`参数可以以JSON格式输出结果，便于进一步处理和分析。

### 文件输出

使用`--output`参数可将结果保存到文件，批量检测时支持CSV格式导出。

## 项目结构

```
cdn_check/
├── __init__.py
├── app.py              # 应用程序主类
├── cli.py              # 命令行接口
├── core/               # 核心功能模块
│   ├── __init__.py
│   ├── cdn_detector.py # CDN检测核心逻辑
│   ├── ip_analyzer.py  # IP分析模块
│   ├── logger.py       # 日志管理
│   ├── db_manager.py   # 数据库管理
│   └── plugin_manager.py # 插件管理
├── plugins/            # 插件目录
│   ├── __init__.py
│   ├── cdn_plugin.py
│   ├── cert_plugin.py
│   ├── dns_plugin.py
│   ├── http_plugin.py
│   └── ip_plugin.py
└── data/               # 数据目录
    ├── cdn/
    │   ├── rules.json  # CDN规则
    │   └── learning_history.json  # 学习历史
    └── cdn_detection.db  # SQLite数据库
```

## 高级功能

### MaxMind GeoIP2数据库集成

工具支持集成MaxMind GeoIP2数据库以获取更准确的IP地理位置和ASN信息。将GeoIP2数据库文件放置在指定目录中即可自动使用。

### 自定义HTTP头规则

可以在配置文件中自定义HTTP头检测规则，用于识别不同的CDN提供商：

```json
"httpheader_check": [
  {
    "name": "Server",
    "pattern": "cloudflare",
    "cdn": "Cloudflare",
    "match_type": "regex"
  },
  {
    "name": "X-CDN",
    "pattern": "fastly",
    "cdn": "Fastly",
    "match_type": "contains"
  }
]
```

### 扩展机器学习功能

可以自定义机器学习模型或集成现有的机器学习框架：

1. 在`ml`目录下创建你的模型类：

```python
# cdn_check/ml/cdn_classifier.py
from sklearn.ensemble import RandomForestClassifier
from cdn_check.core.db_manager import DBManager

class CDNClassifier:
    def __init__(self):
        self.model = RandomForestClassifier()
        self.db = DBManager()
        
    def train(self):
        # 从数据库获取训练数据
        features, labels = self.db.get_training_data()
        # 训练模型
        self.model.fit(features, labels)
        
    def predict(self, features):
        # 预测结果
        return self.model.predict(features)
        
    def evaluate(self, test_features, test_labels):
        # 评估模型
        predictions = self.model.predict(test_features)
        # 计算准确率等指标
        return {
            "accuracy": (predictions == test_labels).mean()
        }
```

2. 在命令行接口中添加相关命令：

```python
@cli.command()
def train_model():
    """训练CDN分类模型"""
    from cdn_check.ml.cdn_classifier import CDNClassifier
    classifier = CDNClassifier()
    classifier.train()
    console.print("[bold green]模型训练完成[/bold green]")
```

## 常见问题

1. **如何提高检测准确率？**
   - 使用最新的规则库
   - 提供反馈以帮助系统自学习
   - 集成MaxMind GeoIP2数据库
   - 导出数据进行专业的机器学习模型训练

2. **检测不到某些CDN？**
   - 可能需要添加新的检测规则
   - 在`config.json`中添加新的HTTP头规则或CNAME模式
   - 通过提供反馈来帮助系统学习新的CDN特征

3. **如何解决IP地理信息获取失败？**
   - 确保MaxMind GeoIP2数据库已正确安装
   - 检查数据库路径配置是否正确

4. **数据库文件变得很大怎么办？**
   - 可以定期清理旧数据或导出重要数据后重新创建数据库
   - 通过调整配置限制原始数据的保存

5. **如何备份数据库？**
   - 简单复制`data/cdn_detection.db`文件即可
   - 也可以使用`export`命令导出重要数据

## 许可证

本项目采用MIT许可证，详情请参阅LICENSE文件。

