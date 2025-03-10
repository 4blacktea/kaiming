# PCAP Analysis System

这是一个基于Web的PCAP文件分析系统，支持上传数据包文件并进行分析，提供流量统计、地理位置信息和可视化展示。

## 功能特点

1. Web界面上传PCAP文件
2. 根据源地址和目的地址统计数据包数量
3. 自动查询IP地址对应的地理位置信息
4. 检测并标识超时和重传的网络流量
5. 使用桑基图等可视化图表展示网络流量分析结果

## 安装要求

- Python 3.8+
- pip包管理器

## 安装步骤

1. 克隆代码库：
```bash
git clone <repository-url>
cd pcap-analysis-system
```

2. 安装依赖：
```bash
pip install -r requirements.txt
```

## 使用方法

1. 启动应用：
```bash
python app.py
```

2. 打开浏览器访问：
```
http://localhost:5000
```

3. 在Web界面上传PCAP文件并等待分析结果

## 注意事项

- 上传文件大小限制为16MB
- 支持的文件格式：.pcap, .pcapng
- 需要网络连接以获取IP地理位置信息

## 技术栈

- 后端：Flask, Scapy
- 前端：Bootstrap 5, ECharts
- 数据可视化：pyecharts
- API：百度IP地理位置API 