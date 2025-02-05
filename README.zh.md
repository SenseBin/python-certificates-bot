# Python-Certificates-Bot
- [English](README.md)
- [简体中文](README.zh.md)
## 概述

Python-Certificates-Bot 是一个使用 ACME 协议从 Let's Encrypt 获取 SSL/TLS 证书的 Python 工具。这个工具自动处理账户注册、订单创建、HTTP-01 验证和证书签发，使您能够轻松地为您的 Web 服务器提供 HTTPS 安全证书。

## 特性
- 生成 ACME 账户
- 创建并完成 SSL/TLS 证书订单
- 处理 HTTP-01 验证
- 自动保存证书、私钥和证书链
- 兼容 Let's Encrypt 和其他基于 ACME 的证书颁发机构

## 安装
下载源码并安装所需的依赖项：

```bash
git clone https://github.com/SenseBin/python-certificates-bot.git
cd python-certificates-bot
pip install requests cryptography
```

## 使用方法
1. 修改 main 函数中的 `account_emails` 为您自己的电子邮件地址。
2. 修改 main 函数中的 `domain_name` 为您需要生成证书的域名。
3. 设置 `challenge_base_dir` 为您服务器的 `$webroot/.well-known/acme-challenge`

运行脚本：
```bash
python python-certificates-bot.py
```
生成的证书文件将在 `cert_output` 目录中。
