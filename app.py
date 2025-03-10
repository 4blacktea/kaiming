import os
from flask import Flask, request, render_template, jsonify
from werkzeug.utils import secure_filename
from scapy.all import *
import pandas as pd
import requests
from pyecharts import options as opts
from pyecharts.charts import Sankey
import json
from collections import defaultdict
from datetime import datetime

app = Flask(__name__, 
           template_folder='app/templates',
           static_folder='app/static')
app.config['UPLOAD_FOLDER'] = 'app/uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

def get_location_info(ip):
    try:
        url = f"http://opendata.baidu.com/api.php?co=&resource_id=6006&oe=utf8&query={ip}"
        response = requests.get(url)
        data = response.json()
        if data.get('data'):
            return data['data'][0].get('location', 'Unknown')
        return 'Unknown'
    except:
        return 'Unknown'

def get_packet_protocol(packet):
    protocols = []
    if TCP in packet:
        protocols.append('TCP')
        # 检查常见的应用层协议
        if packet[TCP].dport == 80 or packet[TCP].sport == 80:
            protocols.append('HTTP')
        elif packet[TCP].dport == 443 or packet[TCP].sport == 443:
            protocols.append('HTTPS')
        elif packet[TCP].dport == 21 or packet[TCP].sport == 21:
            protocols.append('FTP')
        elif packet[TCP].dport == 22 or packet[TCP].sport == 22:
            protocols.append('SSH')
    if UDP in packet:
        protocols.append('UDP')
        if packet[UDP].dport == 53 or packet[UDP].sport == 53:
            protocols.append('DNS')
    if ICMP in packet:
        protocols.append('ICMP')
    if ARP in packet:
        protocols.append('ARP')
    return protocols

def analyze_pcap(filepath, selected_protocols=None):
    packets = rdpcap(filepath)
    
    # 检查是否有时间戳
    has_timestamp = True
    try:
        _ = packets[0].time
    except:
        has_timestamp = False
    
    # 初始化统计数据
    stats = {
        'packet_count': 0,
        'ip_stats': {},
        'retransmissions': [],
        'timeouts': [],
        'sankey_data': [],
        'protocols': defaultdict(int),  # 添加协议统计
        'timeline_data': defaultdict(lambda: defaultdict(int)),  # 添加时间轴数据
        'has_timestamp': has_timestamp,  # 添加时间戳标志
        'ip_list': set()  # 添加IP列表用于前端筛选
    }
    
    if not has_timestamp:
        return stats
    
    # 使用字典来跟踪已处理的IP对
    processed_pairs = defaultdict(int)
    
    # 获取时间范围
    if len(packets) > 0:
        start_time = min(packet.time for packet in packets if hasattr(packet, 'time'))
    
    # IP统计和地理位置
    for packet in packets:
        # 获取数据包的协议
        protocols = get_packet_protocol(packet)
        
        # 更新协议统计
        for protocol in protocols:
            stats['protocols'][protocol] += 1
        
        # 如果指定了协议过滤，检查是否匹配
        if selected_protocols and not any(p in selected_protocols for p in protocols):
            continue
            
        stats['packet_count'] += 1
        
        # 更新时间轴数据
        if hasattr(packet, 'time'):
            # 将时间转换为相对秒数
            relative_time = int(packet.time - start_time)
            # 更新总体时间轴数据
            stats['timeline_data']['all'][relative_time] += 1
            # 更新每个协议的时间轴数据
            for protocol in protocols:
                stats['timeline_data'][protocol][relative_time] += 1
        
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            
            # 添加到IP列表
            stats['ip_list'].add(src_ip)
            stats['ip_list'].add(dst_ip)
            
            # 更新时间轴的IP数据
            if hasattr(packet, 'time'):
                relative_time = int(packet.time - start_time)
                stats['timeline_data'][src_ip][relative_time] += 1
                stats['timeline_data'][dst_ip][relative_time] += 1
            
            if src_ip not in stats['ip_stats']:
                stats['ip_stats'][src_ip] = {
                    'sent': 0,
                    'received': 0,
                    'location': get_location_info(src_ip),
                    'protocols': defaultdict(int)
                }
            if dst_ip not in stats['ip_stats']:
                stats['ip_stats'][dst_ip] = {
                    'sent': 0,
                    'received': 0,
                    'location': get_location_info(dst_ip),
                    'protocols': defaultdict(int)
                }
            
            stats['ip_stats'][src_ip]['sent'] += 1
            stats['ip_stats'][dst_ip]['received'] += 1
            
            # 更新IP的协议统计
            for protocol in protocols:
                stats['ip_stats'][src_ip]['protocols'][protocol] += 1
                stats['ip_stats'][dst_ip]['protocols'][protocol] += 1
            
            # 为桑基图准备数据，确保源IP小于目标IP以避免循环
            pair_key = (min(src_ip, dst_ip), max(src_ip, dst_ip))
            processed_pairs[pair_key] += 1
            
            # 检测重传
            if TCP in packet:
                if packet[TCP].flags & 0x04:  # RST flag
                    stats['retransmissions'].append({
                        'src': src_ip,
                        'dst': dst_ip,
                        'time': packet.time,
                        'protocols': protocols
                    })
    
    # 将处理后的IP对转换为桑基图数据
    for (ip1, ip2), count in processed_pairs.items():
        stats['sankey_data'].append({
            'source': f"{ip1}\n({stats['ip_stats'][ip1]['location']})",
            'target': f"{ip2}\n({stats['ip_stats'][ip2]['location']})",
            'value': count
        })
    
    # 将defaultdict转换为普通dict以便JSON序列化
    stats['protocols'] = dict(stats['protocols'])
    stats['ip_list'] = list(stats['ip_list'])
    for ip in stats['ip_stats']:
        stats['ip_stats'][ip]['protocols'] = dict(stats['ip_stats'][ip]['protocols'])
    
    # 转换时间轴数据为列表格式
    timeline_series = {}
    for key, data in stats['timeline_data'].items():
        if data:  # 只处理非空数据
            timeline_series[key] = {
                'times': list(data.keys()),
                'values': list(data.values())
            }
    stats['timeline_data'] = timeline_series
    
    return stats

def generate_sankey_chart(data):
    # 处理桑基图数据
    nodes = []
    links = []
    node_map = {}
    
    for item in data:
        if item['source'] not in node_map:
            node_map[item['source']] = len(nodes)
            nodes.append({'name': item['source']})
        if item['target'] not in node_map:
            node_map[item['target']] = len(nodes)
            nodes.append({'name': item['target']})
        
        links.append({
            'source': node_map[item['source']],
            'target': node_map[item['target']],
            'value': item['value']
        })
    
    c = (
        Sankey()
        .add(
            "Flow",
            nodes,
            links,
            linestyle_opt=opts.LineStyleOpts(opacity=0.3, curve=0.5, color="source"),
            label_opts=opts.LabelOpts(position="right"),
            node_align="left"
        )
        .set_global_opts(title_opts=opts.TitleOpts(title="Network Traffic Flow"))
    )
    return c.dump_options()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'})
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No selected file'})
    
    # 获取选中的协议
    selected_protocols = request.form.getlist('protocols[]')
    
    if file:
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        
        # 分析PCAP文件
        stats = analyze_pcap(filepath, selected_protocols if selected_protocols else None)
        
        # 生成桑基图数据
        sankey_data = generate_sankey_chart(stats['sankey_data'])
        
        # 清理上传的文件
        os.remove(filepath)
        
        return jsonify({
            'stats': stats,
            'sankey_data': sankey_data
        })

if __name__ == '__main__':
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    app.run(debug=True) 