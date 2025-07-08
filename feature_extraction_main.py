import pandas as pd
import numpy as np
import scapy.all as scapy
from scapy.layers import http
from scipy.stats import entropy, skew
import pywt
import math
import warnings
from collections import defaultdict
from datetime import datetime
import os

from decimal import Decimal
from scapy.layers.tls.record import TLS as TLS_CLASS
from scapy.all import rdpcap


class FeatureExtractor:
    def __init__(self, pcap_file, window_time=2, slide_packets=5):
        self.pcap_file = pcap_file
        self.window_time = window_time  # 时间窗口大小（秒）
        self.slide_packets = slide_packets  # 滑动步长（包数）
        self.packets = []  # 存储所有数据包
        self.features = []  # 存储特征结果
        self.current_window_start = 0  # 当前窗口起始包索引
        self.tcp_flows = defaultdict(dict)  # 跟踪TCP流状态
        self.arp_requests = set()  # 存储ARP请求
        self.ssl_sessions = {}  # 存储SSL会话状态
        self.http_sessions = defaultdict(set)  # 存储HTTP方法
        self.prev_window_stats = {}  # 存储前一个窗口的统计数据
        
        # 状态机违规计数器
        self.state_violations = defaultdict(int)
        
        # 定义TCP状态机规则
        self.tcp_state_rules = {
            'CLOSED': ['SYN_SENT'],
            'SYN_SENT': ['ESTABLISHED', 'CLOSED'],
            'ESTABLISHED': ['FIN_WAIT_1', 'CLOSE_WAIT'],
            'FIN_WAIT_1': ['FIN_WAIT_2', 'CLOSING', 'TIME_WAIT'],
            'FIN_WAIT_2': ['TIME_WAIT'],
            'CLOSE_WAIT': ['LAST_ACK'],
            'LAST_ACK': ['CLOSED'],
            'CLOSING': ['TIME_WAIT'],
            'TIME_WAIT': ['CLOSED']
        }

    def load_packets(self):
        """加载PCAP文件中的所有数据包"""
        print(f"[{datetime.now()}] 开始加载数据包...")
        packets = rdpcap(self.pcap_file)
        self.packets = [(i, pkt) for i, pkt in enumerate(packets)]
        print(f"[{datetime.now()}] 加载完成，共 {len(self.packets)} 个数据包")

    def get_window_packets(self):
        """获取当前窗口的数据包"""
        if self.current_window_start >= len(self.packets):
            return None
            
        start_idx = self.current_window_start
        start_time = self.packets[start_idx][1].time
        
        window_packets = []
        for idx in range(start_idx, len(self.packets)):
            pkt_idx, pkt = self.packets[idx]
            if pkt.time <= start_time + self.window_time:
                window_packets.append((pkt_idx, pkt))
            else:
                break
        
        # 更新下一个窗口起始位置
        self.current_window_start += self.slide_packets
        return window_packets

    def calculate_basic_features(self, window_packets):
        """计算基础流量特征"""
        if not window_packets:
            return {}
            
        start_time = window_packets[0][1].time
        end_time = window_packets[-1][1].time
        duration = end_time - start_time if end_time > start_time else 0.001
        num_packets = len(window_packets)
        
        # 基础统计
        pps = num_packets / duration
        bps = sum(len(pkt) for _, pkt in window_packets) / duration
        packet_sizes = [len(pkt) for _, pkt in window_packets]
        avg_packet_size = np.mean(packet_sizes) if packet_sizes else 0
        packet_size_variance = np.var(packet_sizes) if packet_sizes else 0
        packet_size_skewness = skew(packet_sizes) if len(packet_sizes) > 2 else 0
        small_packet_ratio = sum(1 for size in packet_sizes if size < 64) / num_packets if num_packets else 0
        
        # IP熵计算
        src_ips = []
        dst_ips = []
        for _, pkt in window_packets:
            if scapy.IP in pkt:
                src_ips.append(pkt[scapy.IP].src)
                dst_ips.append(pkt[scapy.IP].dst)
        
        src_ip_entropy = self.calculate_entropy(src_ips)
        dst_ip_entropy = self.calculate_entropy(dst_ips)
        
        return {
            'packets_per_sec': pps,
            'bytes_per_sec': bps,
            'avg_packet_size': avg_packet_size,
            'packet_size_variance': packet_size_variance,
            'packet_size_skewness': packet_size_skewness,
            'small_packet_ratio': small_packet_ratio,
            'src_ip_entropy': src_ip_entropy,
            'dst_ip_entropy': dst_ip_entropy
        }

    def calculate_protocol_features(self, window_packets):
        """计算协议相关特征"""
        if not window_packets:
            return {}
            
        num_packets = len(window_packets)
        tcp_count = 0
        syn_count = 0
        rst_count = 0
        icmp_count = 0
        trdp_count = 0
        arp_response_count = 0
        arp_total_response = 0
        protocols = set()
        
        for _, pkt in window_packets:
            # TCP协议统计
            if scapy.TCP in pkt:
                tcp_count += 1
                if pkt[scapy.TCP].flags & 0x02:  # SYN标志
                    syn_count += 1
                if pkt[scapy.TCP].flags & 0x04:  # RST标志
                    rst_count += 1
                protocols.add('TCP')
            
            # ICMP协议统计
            if scapy.ICMP in pkt:
                icmp_count += 1
                protocols.add('ICMP')
            
            # TRDP协议统计 (假设使用UDP端口17224)
            if scapy.UDP in pkt and (pkt[scapy.UDP].dport == 17224 or pkt[scapy.UDP].sport == 17224):
                trdp_count += 1
                protocols.add('TRDP')
            
            # ARP协议统计
            if scapy.ARP in pkt:
                protocols.add('ARP')
                if pkt[scapy.ARP].op == 2:  # ARP响应
                    arp_total_response += 1
                    if pkt[scapy.ARP].psrc not in self.arp_requests:
                        arp_response_count += 1
                elif pkt[scapy.ARP].op == 1:  # ARP请求
                    self.arp_requests.add(pkt[scapy.ARP].pdst)
        
        # 计算比例
        tcp_syn_ratio = syn_count / tcp_count if tcp_count else 0
        tcp_rst_ratio = rst_count / tcp_count if tcp_count else 0
        icmp_ratio = icmp_count / num_packets if num_packets else 0
        trdp_ratio = trdp_count / num_packets if num_packets else 0
        arp_unsolicited_ratio = arp_response_count / arp_total_response if arp_total_response else 0
        protocol_diversity = len(protocols)
        
        return {
            'tcp_syn_ratio': tcp_syn_ratio,
            'icmp_ratio': icmp_ratio,
            'trdp_ratio': trdp_ratio,
            'tcp_rst_ratio': tcp_rst_ratio,
            'arp_unsolicited_reply_ratio': arp_unsolicited_ratio,
            'protocol_diversity': protocol_diversity
        }

    def calculate_connection_features(self, window_packets):
        """计算连接行为特征"""
        if not window_packets:
            return {}
            
        tcp_retrans_count = 0
        tcp_total = 0
        half_open_count = 0
        connection_attempts = 0
        connection_failures = 0
        flow_completions = 0
        session_durations = []
        window_size_changes = []
        
        # 重置每个窗口的TCP流状态
        window_flows = {}
        
        for pkt_idx, pkt in window_packets:
            if scapy.TCP in pkt and scapy.IP in pkt:
                tcp_total += 1
                ip = pkt[scapy.IP]
                tcp = pkt[scapy.TCP]
                
                # 创建流标识符
                flow_id = (ip.src, ip.dst, tcp.sport, tcp.dport)
                reverse_flow_id = (ip.dst, ip.src, tcp.dport, tcp.sport)
                
                # 记录窗口大小变化
                window_size_changes.append(tcp.window)
                
                # 初始化流状态
                if flow_id not in window_flows:
                    window_flows[flow_id] = {
                        'state': 'CLOSED',
                        'seq': None,
                        'ack': None,
                        'syn_time': None,
                        'fin_time': None,
                        'packets': [],
                        'seq_numbers': set()
                    }
                
                flow = window_flows[flow_id]
                
                # 检测重传
                if tcp.seq in flow['seq_numbers']:
                    tcp_retrans_count += 1
                else:
                    flow['seq_numbers'].add(tcp.seq)
                
                # TCP状态机处理
                prev_state = flow['state']
                flags = tcp.flags
                
                if flags & 0x02:  # SYN
                    if flow['state'] == 'CLOSED':
                        flow['state'] = 'SYN_SENT'
                        flow['syn_time'] = pkt.time
                        connection_attempts += 1
                    # 状态违规检测
                    elif flow['state'] not in ['CLOSED', 'SYN_RECEIVED']:
                        self.state_violations[flow_id] += 1
                
                if flags & 0x10:  # ACK
                    if flow['state'] == 'SYN_SENT':
                        flow['state'] = 'ESTABLISHED'
                    elif flow['state'] == 'FIN_WAIT_1':
                        flow['state'] = 'FIN_WAIT_2'
                
                if flags & 0x01:  # FIN
                    if flow['state'] == 'ESTABLISHED':
                        flow['state'] = 'FIN_WAIT_1'
                        flow['fin_time'] = pkt.time
                    elif flow['state'] == 'CLOSE_WAIT':
                        flow['state'] = 'LAST_ACK'
                
                # 检测半开连接
                if flow['state'] == 'SYN_SENT' and (pkt.time - flow['syn_time']) > 1.0:
                    half_open_count += 1
                    connection_failures += 1
                
                # 检测完成的流
                if flow['syn_time'] and flow['fin_time']:
                    session_durations.append(flow['fin_time'] - flow['syn_time'])
                    flow_completions += 1
        
        # 计算比例
        tcp_retrans_ratio = tcp_retrans_count / tcp_total if tcp_total else 0
        tcp_half_open_ratio = half_open_count / connection_attempts if connection_attempts else 0
        connection_fail_ratio = connection_failures / connection_attempts if connection_attempts else 0
        flow_completion_rate = flow_completions / connection_attempts if connection_attempts else 0
        avg_session_duration = np.mean(session_durations) if session_durations else 0
        window_size_variance = np.var(window_size_changes) if window_size_changes else 0
        
        return {
            'tcp_retransmission_ratio': tcp_retrans_ratio,
            'tcp_half_open_ratio': tcp_half_open_ratio,
            'tcp_window_size_variance': window_size_variance,
            'connection_attempt_fail_ratio': connection_fail_ratio,
            'flow_completion_rate': flow_completion_rate,
            'session_duration_avg': avg_session_duration
        }

    def calculate_timing_features(self, window_packets):
        """计算时序分析特征"""
        if not window_packets or len(window_packets) < 2:
            return {}
            
        # 获取包时间间隔
        timestamps = [pkt.time for _, pkt in window_packets]
        intervals = np.diff(timestamps)
        
        # 突发指数
        # burstiness_index1 = np.var(intervals) if intervals.any() else 0
        # burstiness_index2 = np.mean(intervals) if intervals.any() else 0

        # 先确保 intervals 是 float64 类型的 NumPy 数组
        if len(intervals) > 0:
            intervals_array = np.array(intervals, dtype=np.float64)
            burstiness_index1 = np.var(intervals_array)
            burstiness_index2 = np.mean(intervals_array)
            # entropy_of_intervals = entropy(intervals_array)
            
            # 自相关系数（滞后1）
            if len(intervals_array) > 1:
                autocorr = np.corrcoef(intervals_array[:-1], intervals_array[1:])[0, 1]
            else:
                autocorr = 0.0
        else:
            burstiness_index1 = 0.0
            burstiness_index2 = 0.0
            # entropy_of_intervals = 0.0
            autocorr = 0.0

        
        # 包间隔熵值
        interval_entropy = self.calculate_entropy(intervals)
        
        # 自相关系数
        autocorr = self.calculate_autocorrelation(intervals, lag=1)
        
        # Hurst指数
        hurst_exp = self.calculate_hurst(intervals)
        
        # 小波能量比
        wavelet_energy_ratio = self.calculate_wavelet_energy(intervals)
        
        return {
            'packet_interval_autocorr': autocorr,
            'burstiness_index1': burstiness_index1,
            'burstiness_index2': burstiness_index2,
            'entropy_of_intervals': interval_entropy,
            'hurst_exponent': hurst_exp,
            'wavelet_energy_ratio': wavelet_energy_ratio
        }

    def calculate_payload_features(self, window_packets):
        """计算载荷相关特征"""
        if not window_packets:
            return {}
            
        payload_sizes = []
        payload_entropies = []
        payload_hashes = {}
        ssl_cipher_changes = 0
        ssl_sessions = 0
        
        for _, pkt in window_packets:
            payload = None
            
            # 提取TCP/UDP载荷
            if scapy.TCP in pkt and pkt[scapy.TCP].payload:
                payload = bytes(pkt[scapy.TCP].payload)
            elif scapy.UDP in pkt and pkt[scapy.UDP].payload:
                payload = bytes(pkt[scapy.UDP].payload)
            
            if payload:
                payload_sizes.append(len(payload))
                
                # 计算载荷熵值
                if len(payload) > 0:
                    freq = np.bincount(np.frombuffer(payload, dtype=np.uint8))
                    prob = freq / np.sum(freq)
                    payload_entropies.append(entropy(prob, base=2))
                
                # 计算载荷哈希
                payload_hash = hash(payload)
                payload_hashes[payload_hash] = payload_hashes.get(payload_hash, 0) + 1
            
            # HTTP方法统计
            if pkt.haslayer(http.HTTPRequest):
                http_layer = pkt[http.HTTPRequest]
                src_ip = pkt[scapy.IP].src if scapy.IP in pkt else "unknown"
                method = http_layer.Method.decode('utf-8', errors='ignore')
                self.http_sessions[src_ip].add(method)
            
            # SSL/TLS密码套件变更检测
            if pkt.haslayer(TLS_CLASS):
                tls_layer = pkt[TLS_CLASS]
                if isinstance(tls_layer, scapy.TLSClientHello):
                    src_ip = pkt[scapy.IP].src if scapy.IP in pkt else "unknown"
                    if 'cipher_suites' in tls_layer.fields:
                        cipher_suites = tls_layer.cipher_suites
                        if src_ip in self.ssl_sessions:
                            if self.ssl_sessions[src_ip] != cipher_suites:
                                ssl_cipher_changes += 1
                        self.ssl_sessions[src_ip] = cipher_suites
                        ssl_sessions += 1
        
        # 计算载荷相似度指数
        total_payloads = sum(payload_hashes.values())
        payload_similarity = max(payload_hashes.values()) / total_payloads if total_payloads > 0 else 0
        
        # 计算其他载荷特征
        avg_payload_entropy = np.mean(payload_entropies) if payload_entropies else 0
        payload_size_variance = np.var(payload_sizes) if payload_sizes else 0
        
        # HTTP方法多样性
        http_method_count = sum(len(methods) for methods in self.http_sessions.values())
        
        # SSL密码套件变更频率
        ssl_change_freq = ssl_cipher_changes / ssl_sessions if ssl_sessions else 0
        
        return {
            'payload_similarity_index': payload_similarity,
            'payload_entropy': avg_payload_entropy,
            'payload_size_variance': payload_size_variance,
            'http_method_diversity': http_method_count,
            'ssl_cipher_change_freq': ssl_change_freq
        }

    def calculate_error_features(self, window_packets):
        """计算错误与异常特征"""
        if not window_packets:
            return {}
            
        total_packets = len(window_packets)
        checksum_errors = 0
        ip_fragments = 0
        tcp_checksum_errors = 0
        icmp_unreachable = 0
        dns_format_errors = 0
        
        for _, pkt in window_packets:
            # IP分片检测
            if scapy.IP in pkt and (pkt[scapy.IP].flags & 1 or pkt[scapy.IP].frag > 0):
                ip_fragments += 1
            
            # TCP校验和错误检测
            if scapy.TCP in pkt:
                tcp_layer = pkt[scapy.TCP]
                if not self.verify_tcp_checksum(pkt):
                    tcp_checksum_errors += 1
            
            # ICMP不可达消息
            if scapy.ICMP in pkt and pkt[scapy.ICMP].type == 3:
                icmp_unreachable += 1
            
            # DNS格式错误检测
            if scapy.DNS in pkt:
                try:
                    # 尝试解析DNS包，失败则视为格式错误
                    dns = pkt[scapy.DNS]
                    if dns.qd and dns.qd.qname:
                        pass
                except:
                    dns_format_errors += 1
        
        return {
            'checksum_error_ratio': checksum_errors / total_packets if total_packets else 0,
            'ip_fragmentation_ratio': ip_fragments / total_packets if total_packets else 0,
            'tcp_checksum_error_ratio': tcp_checksum_errors / total_packets if total_packets else 0,
            'icmp_unreachable_ratio': icmp_unreachable / total_packets if total_packets else 0,
            'dns_format_error_ratio': dns_format_errors / total_packets if total_packets else 0
        }

    def calculate_advanced_features(self, window_packets):
        """计算高级行为特征"""
        if not window_packets:
            return {}
            
        # 流量对称性
        request_packets = 0
        response_packets = 0
        
        # 端口和IP扫描检测
        target_ports = set()
        target_ips = set()
        port_changes = 0
        prev_port = None
        
        # 重复模式检测
        payload_patterns = {}
        
        # 连接增长
        new_connections = 0
        prev_connections = self.prev_window_stats.get('connections', 0)
        
        # 当前窗口的流
        connections = set()
        
        for _, pkt in window_packets:
            # 流量方向检测（简化版）
            if scapy.IP in pkt:
                src_ip = pkt[scapy.IP].src
                dst_ip = pkt[scapy.IP].dst
                
                # 假设内部网络IP范围
                if src_ip.startswith('10.') or src_ip.startswith('192.168.'):
                    request_packets += 1
                else:
                    response_packets += 1
                
                # 目标IP统计
                target_ips.add(dst_ip)
                
                # 目标端口统计
                if scapy.TCP in pkt:
                    port = pkt[scapy.TCP].dport
                    target_ports.add(port)
                    
                    # 端口跳变检测
                    if prev_port is not None and port != prev_port:
                        port_changes += 1
                    prev_port = port
                
                # 流标识
                flow_id = (src_ip, dst_ip)
                connections.add(flow_id)
        
        # 计算新连接数
        new_connections = len(connections - self.prev_window_stats.get('prev_connections', set()))
        self.prev_window_stats['prev_connections'] = connections
        self.prev_window_stats['connections'] = len(connections)
        
        # 流量对称指数
        if response_packets > 0:
            flow_symmetry = request_packets / response_packets
        else:
            flow_symmetry = request_packets
        
        # 端口跳变频率
        port_hopping_freq = port_changes / len(window_packets) if window_packets else 0
        
        # IP扫描速度
        scan_speed = len(target_ips) / self.window_time
        
        # 重复模式得分（简化）
        repeated_pattern_score = len(target_ports) / len(window_packets) if window_packets else 0
        
        # 状态违规总数
        state_violation_count = sum(self.state_violations.values())
        
        # 响应/请求比例
        if request_packets > 0:
            response_request_ratio = response_packets / request_packets
        else:
            response_request_ratio = response_packets
        
        # 连接增长率
        if prev_connections > 0:
            connection_ramp_up = new_connections / prev_connections
        else:
            connection_ramp_up = new_connections
        
        return {
            'flow_symmetry_index': flow_symmetry,
            'port_hopping_frequency': port_hopping_freq,
            'address_scan_speed': scan_speed,
            'repeated_pattern_score': repeated_pattern_score,
            'state_transition_violations': state_violation_count,
            'response_request_ratio': response_request_ratio,
            'connection_ramp_up_rate': connection_ramp_up
        }

    def calculate_entropy(self, data):
        """计算数据的香农熵"""
        if data is None or len(data) == 0:  # Proper way to check for empty array/list
            return 0.0


        value_counts = {}
        for item in data:
            # 将不可哈希类型转为 float 或 str
            key = float(item) if isinstance(item, Decimal) else item
            value_counts[key] = value_counts.get(key, 0) + 1

        probs = [count / len(data) for count in value_counts.values()]
        return entropy(probs, base=2)

    def calculate_autocorrelation(self, data, lag=1):
        """计算自相关系数"""
        if len(data) < lag + 1:
            return 0.0

        # 确保所有数据是 float 类型（避免 Decimal/numpy 冲突）
        data = np.array(data, dtype=np.float64)

        mean = np.mean(data)
        var = np.var(data)
        if var == 0:
            return 0.0
            
        cov = np.mean((data[lag:] - mean) * (data[:-lag] - mean))
        return cov / var

    def calculate_hurst(self, data):
        """计算 Hurst 指数"""
        if len(data) < 2:
            return 0.0
        
        # 确保 data 是 float 类型，避免 Decimal 和 numpy 冲突
        data = np.array(data, dtype=np.float64)
        
        # 计算 Hurst 指数
        lags = range(2, min(len(data) // 2, 100))  # 限制最大 lag 避免计算过慢
        tau = [np.sqrt(np.std(np.subtract(data[lag:], data[:-lag]))) for lag in lags]
        
        # 线性回归计算 Hurst 指数
        if len(tau) < 2:
            return 0.0
        
        log_lags = np.log(lags[:len(tau)])
        log_tau = np.log(tau)
        
        # 使用 numpy.polyfit 计算斜率（Hurst 指数）
        hurst, _ = np.polyfit(log_lags, log_tau, 1)
        return float(hurst)  # 返回 Python float 而非 numpy.float64

    def calculate_wavelet_energy(self, data):
        """计算小波能量比"""
        if len(data) < 8:  # 小波变换需要足够的数据点
            return 0.0
            
        try:
            coeffs = pywt.wavedec(data, 'db4', level=min(3, pywt.dwt_max_level(len(data), 'db4')))
            cA = coeffs[0]
            cD = coeffs[1:]
            
            energy_approx = np.sum(np.square(cA))
            energy_detail = sum(np.sum(np.square(c)) for c in cD)
            
            return energy_detail / (energy_approx + energy_detail)
        except:
            return 0.0

    def verify_tcp_checksum(self, packet):
        """验证TCP校验和（简化版）"""
        if scapy.IP not in packet or scapy.TCP not in packet:
            return True
            
        ip = packet[scapy.IP]
        tcp = packet[scapy.TCP]
        
        # 保存原始校验和
        original_checksum = tcp.chksum
        
        # 创建数据包副本并重新计算校验和
        new_pkt = ip / tcp.payload
        new_pkt[scapy.TCP].chksum = None  # 强制重新计算
        new_pkt = scapy.IP(bytes(new_pkt))
        
        # 比较校验和
        return new_pkt[scapy.TCP].chksum == original_checksum

    def extract_features(self):
        """主函数：提取所有特征"""
        self.load_packets()
        
        print(f"[{datetime.now()}] 开始提取特征，时间窗口={self.window_time}秒，滑动步长={self.slide_packets}包")
        # check how many windows we have
        
        window_count = 0
        while True:
            window_packets = self.get_window_packets()
            if not window_packets:
                break
                
            window_count += 1
            if window_count % 10 == 0:
                print(f"[{datetime.now()}] 处理第 {window_count} 个窗口...")
            
            
            # 计算各类特征
            features = {}

            #print ("Starting calculate_basic_features")
            features.update(self.calculate_basic_features(window_packets))
            #print ("Starting calculate_protocol_features")
            features.update(self.calculate_protocol_features(window_packets))
            #print ("Starting calculate_connection_features")
            features.update(self.calculate_connection_features(window_packets))
            #print ("Starting calculate_timing_features")
            features.update(self.calculate_timing_features(window_packets))
            #print ("Starting calculate_payload_features")
            features.update(self.calculate_payload_features(window_packets))
            #print ("Starting calculate_error_features")
            features.update(self.calculate_error_features(window_packets))
            #print ("Starting calculate_advanced_features")
            features.update(self.calculate_advanced_features(window_packets))
            
            # 添加时间窗口信息
            features['window_start'] = window_packets[0][1].time
            features['window_end'] = window_packets[-1][1].time
            features['packet_count'] = len(window_packets)
            
            self.features.append(features)
        
        print(f"[{datetime.now()}] 特征提取完成，共处理 {window_count} 个窗口")
        return self.features

    def save_to_excel(self, output_file):
        """保存特征到Excel文件"""
        if not self.features:
            print("没有特征数据可保存")
            return
            
        df = pd.DataFrame(self.features)
        
        # 确保输出目录存在
        os.makedirs(os.path.dirname(output_file), exist_ok=True)
        
        # 保存到Excel
        df.to_excel(output_file, index=False)
        print(f"[{datetime.now()}] 特征已保存到 {output_file}")

if __name__ == "__main__":

    # input paras
    pack_file = "30satk58.pcapng"
    time_window = 2 
    sliding_size = 1000 
    target_csv = f"output/network_features_{time_window}_{sliding_size}_tmp.csv"
    target_excel = f"output/network_features_{time_window}_{sliding_size}_tmp.xlsx"
    

    # paras initialization
    current_dir = os.path.dirname(os.path.abspath(__file__))

    target_csv = os.path.join(current_dir, target_csv)
    target_excel = os.path.join(current_dir, target_excel)

    pcap_file = os.path.join(current_dir, pack_file)
    
    extractor = FeatureExtractor(
        pcap_file=pcap_file,
        window_time=time_window,      # 2秒时间窗口
        slide_packets=sliding_size     # 每次滑动5个包
    )
    
    features = extractor.extract_features()

    # save to excel
    extractor.save_to_excel(target_excel)
    
    # save to csv
    df = pd.DataFrame(features)
    df.to_csv(target_csv, index=False)

    print(f"特征提取完成，共提取 {len(features)} 个窗口的特征")
    print(f"特征提取完成，csv in {target_csv}")
    print(f"特征提取完成，excel in {target_excel}")

    