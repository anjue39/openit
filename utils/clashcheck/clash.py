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
    with maxminddb.open_database('Country.mmdb') as countrify:
        for i in tqdm(range(int(len(list))), desc="Parse"):
            x = list[i]
            
            # 确保所有字段都是正确的类型
            try:
                # 修复所有字段类型
                for field in x.keys():
                    if field in ['password', 'uuid', 'cipher', 'type', 'name', 'server']:
                        if not isinstance(x[field], str):
                            try:
                                x[field] = str(x[field])
                            except Exception as e:
                                print(f"无法转换字段 {field}: {e}")
                                raise e
                    elif field == 'port':
                        if not isinstance(x[field], int):
                            try:
                                x[field] = int(x[field])
                            except Exception as e:
                                print(f"无法转换端口: {e}")
                                raise e
                    elif field in ['udp', 'tls', 'skip-cert-verify']:
                        if not isinstance(x[field], bool):
                            try:
                                # 尝试将字符串转换为布尔值
                                if isinstance(x[field], str):
                                    if x[field].lower() in ['true', '1', 'yes']:
                                        x[field] = True
                                    elif x[field].lower() in ['false', '0', 'no']:
                                        x[field] = False
                                    else:
                                        print(f"无法转换布尔字段 {field}: {x[field]}")
                                        raise ValueError(f"无效的布尔值: {x[field]}")
                                else:
                                    x[field] = bool(x[field])
                            except Exception as e:
                                print(f"无法转换布尔字段 {field}: {e}")
                                raise e
                
                # 原有的处理逻辑
                try:
                    ip = str(socket.gethostbyname(x["server"]))
                except:
                    ip = str(x["server"])
                try:
                    country = str(countrify.get(ip)['country']['iso_code'])
                except:
                    country = 'UN'
                flagcountry = country
                try:
                    country_count[country] = country_count[country] + 1
                    x['name'] = str(flag.flag(flagcountry)) + " " + country + " " + str(count)
                except:
                    country_count[country] = 1
                    x['name'] = str(flag.flag(flagcountry)) + " " + country + " " + str(count)
                clash['proxies'].append(x)
                clash['proxy-groups'][0]['proxies'].append(x['name'])
                clash['proxy-groups'][1]['proxies'].append(x['name'])
                count = count + 1

            except Exception as e:
                print(f"处理节点时出错: {e}")
                continue

    # 最终验证：确保所有字段都是正确的类型
    valid_proxies = []
    for proxy in clash['proxies']:
        try:
            # 确保所有字段都是正确的类型
            for field in proxy.keys():
                if field in ['password', 'uuid', 'cipher', 'type', 'name', 'server']:
                    if not isinstance(proxy[field], str):
                        proxy[field] = str(proxy[field])
                elif field == 'port':
                    if not isinstance(proxy[field], int):
                        proxy[field] = int(proxy[field])
                elif field in ['udp', 'tls', 'skip-cert-verify']:
                    if not isinstance(proxy[field], bool):
                        if isinstance(proxy[field], str):
                            if proxy[field].lower() in ['true', '1', 'yes']:
                                proxy[field] = True
                            elif proxy[field].lower() in ['false', '0', 'no']:
                                proxy[field] = False
                            else:
                                raise ValueError(f"无效的布尔值: {proxy[field]}")
                        else:
                            proxy[field] = bool(proxy[field])
            
            valid_proxies.append(proxy)
        except Exception as e:
            print(f"最终验证时跳过节点: {e}")
            continue
    
    clash['proxies'] = valid_proxies

    with open(outfile, 'w') as writer:
        yaml.dump(clash, writer, sort_keys=False)


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
                
                # 确保所有字段都是正确的类型
                for field in x.keys():
                    if field in ['password', 'uuid', 'cipher', 'type', 'name', 'server']:
                        if not isinstance(x[field], str):
                            try:
                                x[field] = str(x[field])
                            except Exception as e:
                                print(f"无法转换字段 {field}: {e}")
                                raise e
                    elif field == 'port':
                        if not isinstance(x[field], int):
                            try:
                                x[field] = int(x[field])
                            except Exception as e:
                                print(f"无法转换端口: {e}")
                                raise e
                    elif field in ['udp', 'tls', 'skip-cert-verify']:
                        if not isinstance(x[field], bool):
                            try:
                                # 尝试将字符串转换为布尔值
                                if isinstance(x[field], str):
                                    if x[field].lower() in ['true', '1', 'yes']:
                                        x[field] = True
                                    elif x[field].lower() in ['false', '0', 'no']:
                                        x[field] = False
                                    else:
                                        print(f"无法转换布尔字段 {field}: {x[field]}")
                                        raise ValueError(f"无效的布尔值: {x[field]}")
                                else:
                                    x[field] = bool(x[field])
                            except Exception as e:
                                print(f"无法转换布尔字段 {field}: {e}")
                                raise e
                
                authentication = ''
                x['port'] = int(x['port'])
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

                clash['proxies'].append(x)
                clash['proxy-groups'][0]['proxies'].append(x['name'])
                clash['proxy-groups'][1]['proxies'].append(x['name'])
                count = count + 1

            except Exception as e:
                print(f"处理节点时出错: {e}")
                continue

    return clash
