import os
import yaml
import flag
import socket
import maxminddb
import platform
import psutil
import requests
from tqdm import tqdm
from pathlib import Path

# 全局统计变量
stats = {
    'total_nodes': 0,
    'skipped_nodes': 0,
    'skipped_reasons': {
        'field_conversion': 0,
        'missing_required': 0,
        'unsupported_network': 0,
        'processing_error': 0,
        'duplicate': 0
    },
    'added_nodes': 0,
    'by_country': {}
}

def ensure_string_fields(node):
    """
    确保节点中的特定字段是字符串类型
    如果转换失败或缺少必需字段，返回None表示节点有问题
    
    Args:
        node: 代理节点字典
        
    Returns:
        dict: 处理后的节点字典，或None（如果节点有问题）
    """
    # 必需字段检查
    required_fields = ['type', 'server', 'port']
    for field in required_fields:
        if field not in node:
            stats['skipped_reasons']['missing_required'] += 1
            print(f"跳过节点: 缺少必需字段 '{field}'")
            return None
        elif not node[field]:
            stats['skipped_reasons']['missing_required'] += 1
            print(f"跳过节点: 必需字段 '{field}' 为空")
            return None
    
    # 字段类型转换
    string_fields = ['password', 'uuid', 'cipher', 'type', 'name', 'server']
    for field in string_fields:
        if field in node:
            try:
                # 确保字段是字符串类型
                if not isinstance(node[field], str):
                    node[field] = str(node[field])
                
                # 额外检查：确保password和uuid字段不是空字符串
                if field in ['password', 'uuid'] and not node[field]:
                    stats['skipped_reasons']['field_conversion'] += 1
                    print(f"跳过节点: 字段 '{field}' 为空")
                    return None
                    
            except Exception as e:
                stats['skipped_reasons']['field_conversion'] += 1
                print(f"跳过节点: 字段 '{field}' 转换失败: {e}")
                return None
    
    return node

def push(list, outfile):
    """
    处理节点列表并生成Clash配置文件
    
    Args:
        list: 节点列表
        outfile: 输出文件路径
    """
    stats['total_nodes'] = len(list)
    country_count = {}
    count = 1
    clash = {
        'proxies': [], 
        'proxy-groups': [
            {
                'name': 'automatic', 
                'type': 'url-test', 
                'proxies': [], 
                'url': 'https://www.google.com/favicon.ico',
                'interval': 300
            }, 
            {
                'name': '🌐 Proxy', 
                'type': 'select', 
                'proxies': ['automatic']
            }
        ],
        'rules': ['MATCH,🌐 Proxy']
    }
    
    with maxminddb.open_database('Country.mmdb') as countrify:
        for i in tqdm(range(int(len(list))), desc="Parse"):
            x = list[i].copy()  # 创建节点的副本，避免修改原始数据
            
            # 确保字段是字符串类型，如果失败则跳过节点
            x = ensure_string_fields(x)
            if x is None:
                stats['skipped_nodes'] += 1
                continue
            
            try:
                # 解析服务器IP和国家信息
                try:
                    ip = str(socket.gethostbyname(x["server"]))
                except:
                    ip = str(x["server"])
                
                try:
                    country = str(countrify.get(ip)['country']['iso_code'])
                except:
                    country = 'UN'
                
                # 更新国家统计
                if country not in stats['by_country']:
                    stats['by_country'][country] = 0
                stats['by_country'][country] += 1
                
                # 生成节点名称
                flagcountry = country
                try:
                    country_count[country] = country_count[country] + 1
                    x['name'] = f"{flag.flag(flagcountry)} {country} {count}"
                except:
                    country_count[country] = 1
                    x['name'] = f"{flag.flag(flagcountry)} {country} {count}"
                
                # 最终验证：确保所有字段都是字符串类型
                for field in ['password', 'uuid', 'cipher', 'type', 'name', 'server']:
                    if field in x and not isinstance(x[field], str):
                        raise ValueError(f"字段 '{field}' 不是字符串类型: {type(x[field])}")
                
                # 添加到配置
                clash['proxies'].append(x)
                clash['proxy-groups'][0]['proxies'].append(x['name'])
                clash['proxy-groups'][1]['proxies'].append(x['name'])
                count += 1
                stats['added_nodes'] += 1
                
            except Exception as e:
                stats['skipped_nodes'] += 1
                stats['skipped_reasons']['processing_error'] += 1
                print(f"跳过节点: 处理过程中出现错误: {e}")
                continue

    # 写入配置文件
    with open(outfile, 'w') as writer:
        yaml.dump(clash, writer, sort_keys=False)
    
    # 打印统计信息
    print_stats()

def filter(config):
    """
    过滤和处理原始配置中的代理节点
    
    Args:
        config: 原始配置字典
        
    Returns:
        dict: 处理后的配置字典
    """
    list = config["proxies"]
    stats['total_nodes'] = len(list)
    
    # 支持的加密方式和协议
    ss_supported_ciphers = ['aes-128-gcm', 'aes-256-gcm', 'chacha20-ietf-poly1305'] 
    ssr_supported_obfs = ['plain', 'http_simple', 'http_post', 'random_head', 'tls1.2_ticket_fastauth', 'tls1.2_ticket_auth']
    ssr_supported_protocol = ['origin', 'auth_sha1_v4', 'auth_aes128_md5', 'auth_aes128_sha1', 'auth_chain_a', 'auth_chain_b']
    vmess_supported_ciphers = ['auto', 'aes-128-gcm', 'chacha20-poly1305', 'none']
    
    iplist = {}
    passlist = []
    count = 1
    clash = {
        'proxies': [], 
        'proxy-groups': [
            {
                'name': 'automatic', 
                'type': 'url-test', 
                'proxies': [], 
                'url': 'https://www.google.com/favicon.ico',
                'interval': 300
            }, 
            {
                'name': '🌐 Proxy', 
                'type': 'select', 
                'proxies': ['automatic']
            }
        ],
        'rules': ['MATCH,🌐 Proxy']
    }
    
    with maxminddb.open_database('Country.mmdb') as countrify:
        for i in tqdm(range(int(len(list))), desc="Parse"):
            try:
                x = list[i].copy()  # 创建节点的副本，避免修改原始数据
                
                # 确保字段是字符串类型，如果失败则跳过节点
                x = ensure_string_fields(x)
                if x is None:
                    stats['skipped_nodes'] += 1
                    continue
                
                authentication = ''
                
                # 端口号转换
                try:
                    x['port'] = int(x['port'])
                except:
                    stats['skipped_nodes'] += 1
                    stats['skipped_reasons']['processing_error'] += 1
                    print(f"跳过节点: 端口号转换失败")
                    continue
                
                # 跳过不支持的传输协议
                network = x.get('network', 'tcp')
                if network in ['h2', 'grpc']:
                    stats['skipped_nodes'] += 1
                    stats['skipped_reasons']['unsupported_network'] += 1
                    continue
                
                # 解析服务器IP和国家信息
                try:
                    ip = str(socket.gethostbyname(x["server"]))
                except:
                    ip = x['server']
                
                try:
                    country = str(countrify.get(ip)['country']['iso_code'])
                except:
                    country = 'UN'
                
                # 根据代理类型进行特定验证
                if x['type'] == 'ss':
                    try:
                        if x['cipher'] not in ss_supported_ciphers:
                            continue
                        if ip in iplist and x['port'] in iplist[ip]:
                            stats['skipped_nodes'] += 1
                            stats['skipped_reasons']['duplicate'] += 1
                            continue
                        authentication = 'password'
                        x['name'] = f"{flag.flag(country)} {country} {count} SSS"
                    except:
                        continue
                
                elif x['type'] == 'ssr':
                    try:
                        if x['cipher'] not in ss_supported_ciphers:
                            continue
                        if x['obfs'] not in ssr_supported_obfs:
                            continue
                        if x['protocol'] not in ssr_supported_protocol:
                            continue
                        if ip in iplist and x['port'] in iplist[ip]:
                            stats['skipped_nodes'] += 1
                            stats['skipped_reasons']['duplicate'] += 1
                            continue
                        authentication = 'password'
                        x['name'] = f"{flag.flag(country)} {country} {count} SSR"
                    except:
                        continue
                
                elif x['type'] == 'vmess':
                    try:
                        if 'udp' in x and x['udp'] not in [False, True]:
                            continue
                        if 'tls' in x and x['tls'] not in [False, True]:
                            continue
                        if 'skip-cert-verify' in x and x['skip-cert-verify'] not in [False, True]:
                            continue
                        if x['cipher'] not in vmess_supported_ciphers:
                            continue
                        authentication = 'uuid'
                        x['name'] = f"{flag.flag(country)} {country} {count} VMS"
                    except:
                        continue
                
                elif x['type'] == 'trojan':
                    try:
                        if 'udp' in x and x['udp'] not in [False, True]:
                            continue
                        if 'skip-cert-verify' in x and x['skip-cert-verify'] not in [False, True]:
                            continue
                        authentication = 'password'
                        x['name'] = f"{flag.flag(country)} {country} {count} TJN"
                    except:
                        continue
                
                elif x['type'] == 'snell':
                    try:
                        if 'udp' in x and x['udp'] not in [False, True]:
                            continue
                        if 'skip-cert-verify' in x and x['skip-cert-verify'] not in [False, True]:
                            continue
                        authentication = 'psk'
                        x['name'] = f"{flag.flag(country)} {country} {count} SNL"
                    except:
                        continue
                
                elif x['type'] == 'http':
                    try:
                        if 'tls' in x and x['tls'] not in [False, True]:
                            continue
                        x['name'] = f"{flag.flag(country)} {country} {count} HTT"
                    except:
                        continue
                
                elif x['type'] == 'socks5':
                    try:
                        if 'tls' in x and x['tls'] not in [False, True]:
                            continue
                        if 'udp' in x and x['udp'] not in [False, True]:
                            continue
                        if 'skip-cert-verify' in x and x['skip-cert-verify'] not in [False, True]:
                            continue
                        x['name'] = f"{flag.flag(country)} {country} {count} SK5"
                    except:
                        continue
                
                else:
                    continue  # 不支持的代理类型
                
                # 检查重复节点
                if ip in iplist and x['port'] in iplist[ip]:
                    if authentication and x.get(authentication) in passlist:
                        stats['skipped_nodes'] += 1
                        stats['skipped_reasons']['duplicate'] += 1
                        continue
                    else:
                        if authentication:
                            passlist.append(x[authentication])
                else:
                    try:
                        iplist.setdefault(ip, []).append(x['port'])
                    except:
                        iplist[ip] = [x['port']]
                
                # 更新国家统计
                if country not in stats['by_country']:
                    stats['by_country'][country] = 0
                stats['by_country'][country] += 1
                
                # 最终验证：确保所有字段都是字符串类型
                for field in ['password', 'uuid', 'cipher', 'type', 'name', 'server']:
                    if field in x and not isinstance(x[field], str):
                        raise ValueError(f"字段 '{field}' 不是字符串类型: {type(x[field])}")
                
                # 添加到配置
                clash['proxies'].append(x)
                clash['proxy-groups'][0]['proxies'].append(x['name'])
                clash['proxy-groups'][1]['proxies'].append(x['name'])
                count += 1
                stats['added_nodes'] += 1

            except Exception as e:
                stats['skipped_nodes'] += 1
                stats['skipped_reasons']['processing_error'] += 1
                print(f"跳过节点: 处理过程中出现错误: {e}")
                continue

    # 打印统计信息
    print_stats()
    return clash

def print_stats():
    """打印处理统计信息"""
    print("\n=== 处理统计 ===")
    print(f"总节点数: {stats['total_nodes']}")
    print(f"添加节点数: {stats['added_nodes']}")
    print(f"跳过节点数: {stats['skipped_nodes']}")
    
    if stats['skipped_nodes'] > 0:
        print("跳过原因:")
        for reason, count in stats['skipped_reasons'].items():
            if count > 0:
                print(f"  - {reason}: {count}")
    
    if stats['by_country']:
        print("按国家/地区分布:")
        for country, count in sorted(stats['by_country'].items(), key=lambda x: x[1], reverse=True):
            print(f"  - {country}: {count}")

# 其余函数保持不变...
