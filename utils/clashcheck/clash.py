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
    
    # 创建一个全新的节点列表，使用深拷贝确保不修改原始数据
    import copy
    processed_list = copy.deepcopy(list)
    
    # 第一步：预处理所有节点，确保password和uuid字段是字符串
    print("预处理所有节点...")
    for i, node in enumerate(tqdm(processed_list, desc="Pre-processing")):
        # 处理password字段
        if 'password' in node:
            try:
                # 使用更严格的方法确保是字符串
                if isinstance(node['password'], (int, float)):
                    node['password'] = str(node['password'])
                elif not isinstance(node['password'], str):
                    node['password'] = str(node['password'])
            except Exception as e:
                print(f"无法处理节点 {i} 的password字段: {e}")
                node['password'] = ''  # 设置为空字符串
        
        # 处理uuid字段
        if 'uuid' in node:
            try:
                # 使用更严格的方法确保是字符串
                if isinstance(node['uuid'], (int, float)):
                    node['uuid'] = str(node['uuid'])
                elif not isinstance(node['uuid'], str):
                    node['uuid'] = str(node['uuid'])
            except Exception as e:
                print(f"无法处理节点 {i} 的uuid字段: {e}")
                node['uuid'] = ''  # 设置为空字符串
    
    # 第二步：处理节点并添加到Clash配置
    with maxminddb.open_database('Country.mmdb') as countrify:
        for i, x in enumerate(tqdm(processed_list, desc="Processing")):
            try:
                # 再次确认password和uuid字段是字符串
                if 'password' in x and not isinstance(x['password'], str):
                    try:
                        x['password'] = str(x['password'])
                    except:
                        print(f"无法转换节点 {i} 的password字段，跳过")
                        continue
                
                if 'uuid' in x and not isinstance(x['uuid'], str):
                    try:
                        x['uuid'] = str(x['uuid'])
                    except:
                        print(f"无法转换节点 {i} 的uuid字段，跳过")
                        continue
                
                # 获取IP和国家信息
                try:
                    ip = str(socket.gethostbyname(x["server"]))
                except:
                    ip = str(x["server"])
                
                try:
                    country = str(countrify.get(ip)['country']['iso_code'])
                except:
                    country = 'UN'
                
                # 创建节点名称
                flagcountry = country
                try:
                    country_count[country] = country_count.get(country, 0) + 1
                    x['name'] = f"{flag.flag(flagcountry)} {country} {count}"
                except:
                    country_count[country] = 1
                    x['name'] = f"{flag.flag(flagcountry)} {country} {count}"
                
                # 添加到Clash配置
                clash['proxies'].append(x)
                clash['proxy-groups'][0]['proxies'].append(x['name'])
                clash['proxy-groups'][1]['proxies'].append(x['name'])
                count += 1
                
            except Exception as e:
                print(f"处理节点 {i} 时出错: {e}")
                continue
    
    # 第三步：最终验证和修复
    print("最终验证和修复...")
    indices_to_remove = []
    for i, proxy in enumerate(clash['proxies']):
        # 检查password字段
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
    
    # 第四步：使用自定义的YAML序列化器
    class StrictStringDumper(yaml.SafeDumper):
        def represent_str(self, data):
            # 确保所有字符串都被正确表示
            return super().represent_str(data)
        
        def represent_float(self, data):
            # 将浮点数转换为字符串
            return self.represent_str(str(data))
        
        def represent_int(self, data):
            # 将整数转换为字符串
            return self.represent_str(str(data))
    
    # 注册自定义表示器
    yaml.add_representer(str, StrictStringDumper.represent_str)
    yaml.add_representer(float, StrictStringDumper.represent_float)
    yaml.add_representer(int, StrictStringDumper.represent_int)
    
    # 第五步：写入文件
    print("写入文件...")
    with open(outfile, 'w') as writer:
        yaml.dump(clash, writer, sort_keys=False, Dumper=StrictStringDumper)
    
    # 第六步：手动修复输出文件
    print("手动修复输出文件...")
    with open(outfile, 'r') as reader:
        content = reader.read()
    
    # 使用正则表达式修复所有password字段
    import re
    # 修复格式: password: 123.456 -> password: "123.456"
    content = re.sub(r'password: (\d+\.?\d*)', r'password: "\1"', content)
    # 修复格式: password: 123 -> password: "123"
    content = re.sub(r'password: (\d+)', r'password: "\1"', content)
    
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
