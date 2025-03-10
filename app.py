import os
from flask import Flask, request, render_template, jsonify
from werkzeug.utils import secure_filename
from scapy.all import *
import pandas as pd
import requests
from pyecharts import options as opts
from pyecharts.charts import Sankey
import json

app = Flask(__name__)
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

def analyze_pcap(filepath):
    packets = rdpcap(filepath)
    
    # 初始化统计数据
    stats = {
        'packet_count': len(packets),
        'ip_stats': {},
        'retransmissions': [],
        'timeouts': [],
        'sankey_data': []
    }
    
    # IP统计和地理位置
    for packet in packets:
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            
            if src_ip not in stats['ip_stats']:
                stats['ip_stats'][src_ip] = {
                    'sent': 0,
                    'received': 0,
                    'location': get_location_info(src_ip)
                }
            if dst_ip not in stats['ip_stats']:
                stats['ip_stats'][dst_ip] = {
                    'sent': 0,
                    'received': 0,
                    'location': get_location_info(dst_ip)
                }
            
            stats['ip_stats'][src_ip]['sent'] += 1
            stats['ip_stats'][dst_ip]['received'] += 1
            
            # 为桑基图准备数据
            stats['sankey_data'].append({
                'source': f"{src_ip}\n({stats['ip_stats'][src_ip]['location']})",
                'target': f"{dst_ip}\n({stats['ip_stats'][dst_ip]['location']})",
                'value': 1
            })
            
            # 检测重传
            if TCP in packet:
                if packet[TCP].flags & 0x04:  # RST flag
                    stats['retransmissions'].append({
                        'src': src_ip,
                        'dst': dst_ip,
                        'time': packet.time
                    })
    
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
            
        # 合并相同source-target的值
        link_found = False
        for link in links:
            if link['source'] == node_map[item['source']] and link['target'] == node_map[item['target']]:
                link['value'] += item['value']
                link_found = True
                break
        if not link_found:
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
    
    if file:
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        
        # 分析PCAP文件
        stats = analyze_pcap(filepath)
        
        # 生成桑基图数据
        sankey_data = generate_sankey_chart(stats['sankey_data'])
        
        return jsonify({
            'stats': stats,
            'sankey_data': sankey_data
        })

if __name__ == '__main__':
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    app.run(debug=True) 