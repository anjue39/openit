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


def push(list, outfile):
    country_count = {}
    count = 1
    clash = {'proxies': [], 'proxy-groups': [
            {'name': 'automatic', 'type': 'url-test', 'proxies': [], 'url': 'https://www.google.com/favicon.ico',
             'interval': 300}, {'name': '🌐 Proxy', 'type': 'select', 'proxies': ['automatic']}],
             'rules': ['MATCH,🌐 Proxy']}
    
    # 在开始处理前，先检查原始数据中的password字段类型
    print("检查原始数据中的password字段类型...")
    problematic_nodes = []
    for i, node in enumerate(list):
        if 'password' in node and not isinstance(node['password'], str):
            print(f"原始节点 {i} 的password字段类型: {type(node['password'])}")
            problematic_nodes.append(i)
    
    # 创建一个全新的节点列表，确保所有字段类型正确
    processed_nodes = []
    
    with maxminddb.open_database('Country.mmdb') as countrify:
        for i in tqdm(range(len(list)), desc="Processing"):
            original_node = list[i]
            
            # 创建一个新节点，确保所有字段都是正确的类型
            new_node = {}
            
            # 复制所有字段，并确保类型正确
            for key, value in original_node.items():
                # 特殊处理password和uuid字段
                if key == 'password' or key == 'uuid':
                    # 强制转换为字符串
                    try:
                        # 使用更严格的方法确保是字符串
                        if isinstance(value, (int, float)):
                            new_node[key] = str(int(value)) if isinstance(value, int) else str(float(value))
                        else:
                            new_node[key] = str(value)
                    except Exception as e:
                        # 如果无法转换，跳过此节点
                        print(f"无法将{key}转换为字符串，跳过节点 {i}: {e}")
                        new_node = None
                        break
                else:
                    # 对于其他字段，直接复制
                    new_node[key] = value
            
            # 如果节点无效，跳过
            if new_node is None:
                continue
                
            # 确保必要的字段存在
            if 'password' not in new_node:
                new_node['password'] = ''
            if 'uuid' not in new_node:
                new_node['uuid'] = ''
                
            # 处理服务器和国家信息
            try:
                ip = str(socket.gethostbyname(new_node["server"]))
            except:
                ip = str(new_node["server"])
            
            try:
                country = str(countrify.get(ip)['country']['iso_code'])
            except:
                country = 'UN'
            
            # 创建节点名称
            try:
                country_count[country] = country_count.get(country, 0) + 1
                new_node['name'] = f"{flag.flag(country)} {country} {count}"
            except:
                country_count[country] = 1
                new_node['name'] = f"{flag.flag(country)} {country} {count}"
            
            # 最终确认password和uuid字段是字符串
            if 'password' in new_node and not isinstance(new_node['password'], str):
                try:
                    new_node['password'] = str(new_node['password'])
                    print(f"最终检查时强制转换password，节点 {i}")
                except:
                    print(f"最终检查时无法转换password，跳过节点 {i}")
                    continue
            
            if 'uuid' in new_node and not isinstance(new_node['uuid'], str):
                try:
                    new_node['uuid'] = str(new_node['uuid'])
                    print(f"最终检查时强制转换uuid，节点 {i}")
                except:
                    print(f"最终检查时无法转换uuid，跳过节点 {i}")
                    continue
            
            # 添加到处理后的节点列表
            processed_nodes.append(new_node)
            
            # 添加到Clash配置
            clash['proxies'].append(new_node)
            clash['proxy-groups'][0]['proxies'].append(new_node['name'])
            clash['proxy-groups'][1]['proxies'].append(new_node['name'])
            count += 1
    
    # 最终验证
    indices_to_remove = []
    for i, proxy in enumerate(clash['proxies']):
        if 'password' in proxy and not isinstance(proxy['password'], str):
            print(f"发现非字符串password，移除节点 {i}: {proxy.get('name', 'unknown')}")
            print(f"password值: {proxy['password']}, 类型: {type(proxy['password'])}")
            indices_to_remove.append(i)
    
    # 逆序移除有问题的代理
    for i in sorted(indices_to_remove, reverse=True):
        removed_proxy = clash['proxies'].pop(i)
        for group in clash['proxy-groups']:
            if removed_proxy.get('name') in group['proxies']:
                group['proxies'].remove(removed_proxy.get('name'))
    
    # 创建一个自定义的YAML序列化器，确保所有字段都是字符串
    class StrictStringDumper(yaml.SafeDumper):
        def represent_data(self, data):
            # 如果数据是数字类型，转换为字符串
            if isinstance(data, (int, float)):
                return super().represent_data(str(data))
            # 对于其他类型，使用默认表示方法
            return super().represent_data(data)
    
    # 写入文件
    with open(outfile, 'w') as writer:
        yaml.dump(clash, writer, sort_keys=False, Dumper=StrictStringDumper)
    
    # 验证输出文件
    print("验证输出文件...")
    with open(outfile, 'r') as reader:
        content = reader.read()
        # 检查是否有数字类型的password字段
        import re
        password_pattern = r'password: (\d+\.?\d*)'
        matches = re.findall(password_pattern, content)
        if matches:
            print(f"警告: 发现数字类型的password字段: {matches}")
    
    # 尝试手动修复输出文件
    print("尝试手动修复输出文件...")
    with open(outfile, 'r') as reader:
        content = reader.read()
    
    # 使用正则表达式将所有数字类型的password字段转换为字符串
    content = re.sub(r'password: (\d+\.?\d*)', r"password: '\1'", content)
    
    # 写入修复后的内容
    with open(outfile, 'w') as writer:
        writer.write(content)
    
    print(f"成功处理 {len(clash['proxies'])} 个代理节点")


def checkenv():
    operating_system = str(platform.system() + '/' +  platform.machine() + ' with ' + platform.node())
    print('Try to run Clash on '+ operating_system)
    if operating_system.startswith('Darwin'):
        if 'arm64' in operating_system:
            clashname='./clash-darwin-arm64'
        elif 'x86_64' in operating_system:
            clashname='./clash-darwin-amd64'
        else:
            print('System is supported(Darwin) but Architecture is not supported.')
            exit(1)
    elif operating_system.startswith('Linux'):
        if 'x86_64' in operating_system:
            clashname='./clash-linux-amd64'
        elif 'aarch64' in operating_system:
            clashname='./clash-linux-arm64'
        else:
            print('System is supported(Linux) but Architecture is not supported.')
            exit(1)
    elif operating_system.startswith('Windows'):
        if 'AMD64' in operating_system:
            clashname='clash-windows-amd64.exe'
        else:
            print('System is supported(Windows) but Architecture is not supported.')
            exit(1)
    else:
        print('System is not supported.')
        exit(1)

    return clashname, operating_system


def checkuse(clashname, operating_system):
    pids = psutil.process_iter()
    for pid in pids:
        if(pid.name() == clashname):
            if operating_system.startswith('Darwin'):
                os.kill(pid.pid,9)
            elif operating_system.startswith('Linux'):
                os.kill(pid.pid,9)
            elif operating_system.startswith('Windows'):
                os.popen('taskkill.exe /pid:'+str(pid.pid))
            else:
                print(clashname, str(pid.pid) + " ← kill to continue")
                exit(1)


def filter(config):
    list = config["proxies"]
    ss_supported_ciphers = ['aes-128-gcm', 'aes-256-gcm', 'chacha20-ietf-poly1305'] 
    ssr_supported_obfs = ['plain', 'http_simple', 'http_post', 'random_head', 'tls1.2_ticket_fastauth', 'tls1.2_ticket_auth']
    ssr_supported_protocol = ['origin', 'auth_sha1_v4', 'auth_aes128_md5', 'auth_aes128_sha1', 'auth_chain_a', 'auth_chain_b']
    vmess_supported_ciphers = ['auto', 'aes-128-gcm', 'chacha20-poly1305', 'none']
    iplist = {}
    passlist = []
    count = 1
    clash = {'proxies': [], 'proxy-groups': [
            {'name': 'automatic', 'type': 'url-test', 'proxies': [], 'url': 'https://www.google.com/favicon.ico',
             'interval': 300}, {'name': '🌐 Proxy', 'type': 'select', 'proxies': ['automatic']}],
             'rules': ['MATCH,🌐 Proxy']}
    with maxminddb.open_database('Country.mmdb') as countrify:
        for i in tqdm(range(int(len(list))), desc="Parse"):
            try:
                x = list[i]
                authentication = ''
                x['port'] = int(x['port'])
                
                # 处理password字段 - 确保是字符串类型
                password_valid = True
                if 'password' in x:
                    try:
                        x['password'] = str(x['password'])
                    except Exception as e:
                        print(f"无法将password转换为字符串，跳过节点 {i}: {e}")
                        password_valid = False
                else:
                    x['password'] = ''
                
                # 处理uuid字段 - 确保是字符串类型
                uuid_valid = True
                if 'uuid' in x:
                    try:
                        x['uuid'] = str(x['uuid'])
                    except Exception as e:
                        print(f"无法将uuid转换为字符串，跳过节点 {i}: {e}")
                        uuid_valid = False
                else:
                    x['uuid'] = ''
                
                # 如果password或uuid转换失败，跳过此节点
                if not password_valid or not uuid_valid:
                    continue
                
                # 新增逻辑：直接跳过所有 h2/grpc 节点
                network = x.get('network', 'tcp')  # 获取传输协议类型
                if network in ['h2', 'grpc']:
                    continue  # 直接舍弃，不处理后续逻辑
                
                try:
                    ip = str(socket.gethostbyname(x["server"]))
                except:
                    ip = x['server']
                try:
                    country = str(countrify.get(ip)['country']['iso_code'])
                except:
                    country = 'UN'                   
                if x['type'] == 'ss':
                    try:
                        if x['cipher'] not in ss_supported_ciphers:
                            continue
                        if ip in iplist:
                            continue
                        else:
                            iplist[ip] = []
                            iplist[ip].append(x['port'])
                        x['name'] = str(flag.flag(country)) + ' ' + str(country) + ' ' + str(count) + ' ' + 'SSS'
                        authentication = 'password'
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
                        if ip in iplist:
                            continue
                        else:
                            iplist.append(ip)
                            iplist[ip].append(x['port'])
                        authentication = 'password'
                        x['name'] = str(flag.flag(country)) + ' ' + str(country) + ' ' + str(count) + ' ' + 'SSR'
                    except:
                        continue
                elif x['type'] == 'vmess':
                    try:
                        if 'udp' in x:
                            if x['udp'] not in [False, True]:
                                continue
                        if 'tls' in x:
                            if x['tls'] not in [False, True]:
                                continue
                        if 'skip-cert-verify' in x:
                            if x['skip-cert-verify'] not in [False, True]:
                                continue
                        if x['cipher'] not in vmess_supported_ciphers:
                            continue
                        x['name'] = str(flag.flag(country)) + ' ' + str(country) + ' ' + str(count) + ' ' + 'VMS'
                        authentication = 'uuid'
                    except:
                        continue
                elif x['type'] == 'trojan':
                    try:
                        if 'udp' in x:
                            if x['udp'] not in [False, True]:
                                continue
                        if 'skip-cert-verify' in x:
                            if x['skip-cert-verify'] not in [False, True]:
                                continue
                        x['name'] = str(flag.flag(country)) + ' ' + str(country) + ' ' + str(count) + ' ' + 'TJN'
                        authentication = 'password'
                    except:
                        continue
                elif x['type'] == 'snell':
                    try:
                        if 'udp' in x:
                            if x['udp'] not in [False, True]:
                                continue
                        if 'skip-cert-verify' in x:
                            if x['skip-cert-verify'] not in [False, True]:
                                continue
                        x['name'] = str(flag.flag(country)) + ' ' + str(country) + ' ' + str(count) + ' ' + 'SNL'
                        authentication = 'psk'
                    except:
                        continue
                elif x['type'] == 'http':
                    try:
                        if 'tls' in x:
                            if x['tls'] not in [False, True]:
                                continue
                        x['name'] = str(flag.flag(country)) + ' ' + str(country) + ' ' + str(count) + ' ' + 'HTT'
                        # authentication = 'userpass'
                    except:
                        continue
                elif x['type'] == 'socks5':
                    try:
                        if 'tls' in x:
                            if x['tls'] not in [False, True]:
                                continue
                        if 'udp' in x:
                            if x['udp'] not in [False, True]:
                                continue
                        if 'skip-cert-verify' in x:
                            if x['skip-cert-verify'] not in [False, True]:
                                continue
                        x['name'] = str(flag.flag(country)) + ' ' + str(country) + ' ' + str(count) + ' ' + 'SK5'
                        # authentication = 'userpass'
                
                    except:
                        continue
                else:
                    continue

                if ip in iplist and x['port'] in iplist[ip]:
                    if x[authentication] in passlist:
                        continue
                    else:
                        passlist.append(x[authentication])
                else:
                    try:
                        iplist[ip].append(x['port'])
                    except:
                        iplist[ip] = []
                        iplist[ip].append(x['port'])

                # 最终确认password和uuid字段是字符串类型
                if 'password' in x and not isinstance(x['password'], str):
                    try:
                        x['password'] = str(x['password'])
                    except:
                        print(f"最终检查时无法转换password，跳过节点 {i}")
                        continue
                
                if 'uuid' in x and not isinstance(x['uuid'], str):
                    try:
                        x['uuid'] = str(x['uuid'])
                    except:
                        print(f"最终检查时无法转换uuid，跳过节点 {i}")
                        continue

                clash['proxies'].append(x)
                clash['proxy-groups'][0]['proxies'].append(x['name'])
                clash['proxy-groups'][1]['proxies'].append(x['name'])
                count = count + 1

            except Exception as e:
                print(f'处理节点时出错 {i}: {e}')
                continue

    return clash
