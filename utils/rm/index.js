const fs = require('fs');
const location = require('./location');
const config = require('./config');

// 读取输入文件和flags配置
let urls = fs.readFileSync('./url', 'utf8');
let flags = JSON.parse(fs.readFileSync('./flags.json', 'utf8'));

let urlList = urls.split('\n');
let resList = [];
let finalList = [];
let finalURLs = [];
let countryList = ['unknown'];
let emojiList = [''];
let countryCount = { unknown: 0 };
let urlCountryList = { unknown: [] };

async function run() {
    // 初始化国家和emoji列表
    flags.forEach(flag => {
        countryList.push(flag.code);
        emojiList.push(flag.emoji);
        countryCount[flag.code] = 0;
        urlCountryList[flag.code] = [];
    });

    // 解析URL
    for (let url of urlList) {
        try {
            let protocol = url.split('://')[0];
            switch (protocol) {
                case 'vmess':
                    let vmessData = Buffer.from(url.split('://')[1], 'base64').toString('utf-8');
                    let vmessJSON = JSON.parse(vmessData);
                    if (!vmessJSON.add) throw new Error('vmess地址缺失');
                    vmessJSON.ps = null;
                    resList.push({ type: 'vmess', data: vmessJSON, address: vmessJSON.add });
                    break;
                case 'trojan':
                    let trojanData = url.split('://')[1].split('#')[0];
                    let trojanAddress = trojanData.split('@')[1]?.split(':')[0];
                    if (!trojanAddress) throw new Error('trojan地址格式错误');
                    resList.push({ type: 'trojan', data: trojanData, address: trojanAddress });
                    break;
                case 'ss':
                    let ssData = url.split('://')[1].split('#')[0];
                    let ssAddress = ssData.split('@')[1]?.split(':')[0];
                    if (!ssAddress) throw new Error('ss地址格式错误');
                    resList.push({ type: 'ss', data: ssData, address: ssAddress });
                    break;
                case 'ssr':
                    let ssrData = Buffer.from(url.split('://')[1], 'base64').toString('utf-8');
                    let ssrAddress = ssrData.split(':')[0];
                    resList.push({
                        type: 'ssr',
                        data: ssrData.replace(/remarks=.*?(?=&)/, "remarks={name}&"),
                        address: ssrAddress
                    });
                    break;
                case 'https':
                    let httpsData = url.split('://')[1].split('#')[0];
                    let httpsAddress = Buffer.from(httpsData.split('?')[0], "base64").toString('utf8').split('@')[1]?.split(':')[0];
                    if (!httpsAddress) throw new Error('https地址格式错误');
                    resList.push({ type: 'https', data: httpsData, address: httpsAddress });
                    break;
                default:
                    console.log(`未知协议类型: ${protocol}`);
                    break;
            }
        } catch (e) {
            console.log(`解析节点错误: ${e.message}, URL: ${url}`);
        }
    }

    // 去重
    let uniqueResList = Array.from(new Set(resList.map(item => JSON.stringify(item)))).map(item => JSON.parse(item));

    // 批量测试国家
    for (let item of uniqueResList) {
        try {
            item.country = await location.get(item.address);
        } catch (e) {
            item.country = 'unknown';
            console.log(`获取国家信息失败: ${e.message}, 地址: ${item.address}`);
        }
        finalList.push(item);
    }

    // 生成最终链接列表
    for (let item of finalList) {
        let country = item.country;
        countryCount[country] = (countryCount[country] || 0) + 1;
        let name = `${emojiList[countryList.indexOf(country)]}${country} ${countryCount[country]}${config.nodeAddName}`;

        // 确保 urlCountryList[country] 已经初始化
        if (!urlCountryList[country]) {
            urlCountryList[country] = [];
        }

        try {
            switch (item.type) {
                case 'vmess':
                    item.data.ps = name;
                    urlCountryList[country].push(`vmess://${Buffer.from(JSON.stringify(item.data), 'utf8').toString('base64')}`);
                    break;
                case 'trojan':
                    urlCountryList[country].push(`trojan://${item.data}#${encodeURIComponent(name)}`);
                    break;
                case 'ss':
                    urlCountryList[country].push(`ss://${item.data}#${encodeURIComponent(name)}`);
                    break;
                case 'ssr':
                    urlCountryList[country].push(`ssr://${Buffer.from(item.data.replace('{name}', Buffer.from(name, 'utf8').toString('base64')), 'utf8').toString('base64')}`);
                    break;
                case 'https':
                    urlCountryList[country].push(`https://${item.data}#${encodeURIComponent(name)}`);
                    break;
                default:
                    console.log(`未知节点类型: ${item.type}`);
                    break;
            }
        } catch (e) {
            console.log(`生成链接错误: ${e.message}, 类型: ${item.type}`);
        }
    }

    // 将所有生成的URL合并
    for (let country in urlCountryList) {
        finalURLs.push(...urlCountryList[country]);
    }

    console.log(`去重改名完成\n一共${urlList.length}个节点，去重${urlList.length - finalURLs.length}个节点，剩余${finalURLs.length}个节点`);
    // 输出到文件
    fs.writeFileSync('./out', finalURLs.join('\n'));
}

run().catch(e => console.error(`运行时出错: ${e.message}`));
