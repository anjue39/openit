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
    
    # 创建一个新列表，确保所有字段类型正确
    processed_list = []
    
    for i, node in enumerate(tqdm(list, desc="Pre-processing")):
        # 创建节点的深拷贝，避免修改原始数据
        processed_node = node.copy()
        
        # 确保所有字段都是正确的类型
        try:
            # 处理password字段
            if 'password' in processed_node:
                if not isinstance(processed_node['password'], str):
                    processed_node['password'] = str(processed_node['password'])
            
            # 处理uuid字段
            if 'uuid' in processed_node:
                if not isinstance(processed_node['uuid'], str):
                    processed_node['uuid'] = str(processed_node['uuid'])
            
            # 处理port字段
            if 'port' in processed_node:
                if not isinstance(processed_node['port'], int):
                    processed_node['port'] = int(processed_node['port'])
            
            # 处理server字段
            if 'server' in processed_node:
                if not isinstance(processed_node['server'], str):
                    processed_node['server'] = str(processed_node['server'])
            
            processed_list.append(processed_node)
            
        except Exception as e:
            print(f"Error processing node {i}: {e}")
            continue
    
    with maxminddb.open_database('Country.mmdb') as countrify:
        for i, x in enumerate(tqdm(processed_list, desc="Processing")):
            try:
                # 再次确认password字段是字符串
                if 'password' in x and not isinstance(x['password'], str):
                    x['password'] = str(x['password'])
                
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
                
                # 最终确认password字段是字符串
                if 'password' in x and not isinstance(x['password'], str):
                    x['password'] = str(x['password'])
                
                # 添加到Clash配置
                clash['proxies'].append(x)
                clash['proxy-groups'][0]['proxies'].append(x['name'])
                clash['proxy-groups'][1]['proxies'].append(x['name'])
                count += 1
                
            except Exception as e:
                print(f"Error adding node {i} to clash config: {e}")
                continue
    
    # 最终验证和修复
    for i, proxy in enumerate(clash['proxies']):
        # 检查并修复password字段
        if 'password' in proxy and not isinstance(proxy['password'], str):
            print(f"Final conversion for proxy {i}: {proxy.get('name', 'unknown')}")
            try:
                proxy['password'] = str(proxy['password'])
            except Exception as e:
                print(f"Failed to convert password for proxy {i}: {e}")
                # 移除有问题的代理
                clash['proxies'].pop(i)
                # 从proxy-groups中移除
                for group in clash['proxy-groups']:
                    if proxy.get('name') in group['proxies']:
                        group['proxies'].remove(proxy.get('name'))
    
    # 写入文件前再次检查
    for proxy in clash['proxies']:
        if 'password' in proxy and not isinstance(proxy['password'], str):
            print(f"WARNING: Proxy {proxy.get('name', 'unknown')} still has non-string password: {type(proxy['password'])}")
    
    # 写入文件
    with open(outfile, 'w') as writer:
        yaml.dump(clash, writer, sort_keys=False)
    
    print(f"Successfully processed {len(clash['proxies'])} proxies")
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
                
                # 统一 password 字段为字符串类型 - 移动到更早的位置
                if 'password' in x:
                    try:
                        x['password'] = str(x['password'])
                    except Exception as e:
                        print(f"Error processing password for node {x.get('name', 'unknown')}: {e}")
                        x['password'] = ''  # 如果处理失败，设置为空字符串
                else:
                    x['password'] = ''  # 如果字段缺失，设置默认值
                
                # 新增逻辑：直接跳过所有 h2/grpc 节点
                network = x.get('network', 'tcp')  # 获取传输协议类型
                if network in ['h2', 'grpc']:
                    continue  # 直接舍弃，不处理后续逻辑
                
                # 统一 uuid 字段为字符串类型（如果有）
                if 'uuid' in x:
                    try:
                        x['uuid'] = str(x['uuid'])
                    except Exception as e:
                        print(f"Error processing uuid for node {x.get('name', 'unknown')}: {e}")
                        x['uuid'] = ''  # 如果处理失败，设置为空字符串
                
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
                            ss_omit_cipher_unsupported = ss_omit_cipher_unsupported + 1
                            continue
                        if ip in iplist:
                            ss_omit_ip_dupe = ss_omit_ip_dupe + 1
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

                clash['proxies'].append(x)
                clash['proxy-groups'][0]['proxies'].append(x['name'])
                clash['proxy-groups'][1]['proxies'].append(x['name'])
                count = count + 1

            except:
                #print('shitwentwrong' + str(x))
                continue

    return clash
