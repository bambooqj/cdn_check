"""
命令行接口 - 用于从命令行调用CDN检测工具
"""

import os
import sys
import json
import asyncio
import click
import tempfile
import csv
from typing import List, Dict, Any, Optional
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.rule import Rule
from rich.tree import Tree
from rich.pretty import Pretty
from rich.progress import Progress

from cdn_check.app import CDNCheckApp
from cdn_check.core.plugin_manager import plugin_manager
from cdn_check.core.logger import logger_manager
from cdn_check.core.db_manager import DBManager

console = Console()

# 全局变量，用于保存最近的检测结果
_last_detection_result = None
_last_detection_domain = None
_last_result_cache_file = os.path.join(tempfile.gettempdir(), "cdn_check_last_result.json")

def _save_last_detection_result(result, domain):
    """保存最近的检测结果到全局变量和临时文件"""
    global _last_detection_result, _last_detection_domain
    _last_detection_result = result
    _last_detection_domain = domain
    
    # 同时保存到临时文件，以便不同进程也能访问
    try:
        with open(_last_result_cache_file, 'w', encoding='utf-8') as f:
            json.dump({
                'result': result,
                'domain': domain
            }, f, indent=2, ensure_ascii=False)
    except Exception as e:
        console.print(f"[yellow]警告: 无法保存检测结果到临时文件: {str(e)}[/yellow]")

def _load_last_detection_result():
    """从全局变量或临时文件加载最近的检测结果"""
    global _last_detection_result, _last_detection_domain
    
    # 如果全局变量中有结果，直接返回
    if _last_detection_result is not None:
        return _last_detection_result, _last_detection_domain
    
    # 否则尝试从临时文件加载
    try:
        if os.path.exists(_last_result_cache_file):
            with open(_last_result_cache_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
                _last_detection_result = data.get('result')
                _last_detection_domain = data.get('domain')
                return _last_detection_result, _last_detection_domain
    except Exception as e:
        console.print(f"[yellow]警告: 无法从临时文件加载检测结果: {str(e)}[/yellow]")
    
    return None, None

@click.group()
@click.version_option(version='0.1.0')
@click.option('--config', '-c', help='配置文件路径', default='config.json')
@click.option('--log-level', type=click.Choice(['debug', 'info', 'warning', 'error', 'critical']), help='日志级别')
@click.pass_context
def cli(ctx, config, log_level):
    """CDN检测工具 - 一个插件化的网络情报分析框架"""
    # 保存配置到上下文
    ctx.ensure_object(dict)
    ctx.obj['config'] = config
    
    # 加载配置文件
    try:
        if os.path.exists(config):
            # 初始化日志
            logger_manager.configure(config_path=config)
            
            # 如果命令行指定了日志级别，覆盖配置文件中的设置
            if log_level:
                import logging
                level_map = {
                    'debug': logging.DEBUG,
                    'info': logging.INFO,
                    'warning': logging.WARNING,
                    'error': logging.ERROR,
                    'critical': logging.CRITICAL
                }
                logging.getLogger().setLevel(level_map[log_level])
        else:
            console.print(f"[bold red]警告: 配置文件 {config} 不存在，将使用默认配置[/bold red]")
            logger_manager.configure()
    except Exception as e:
        console.print(f"[bold red]初始化日志系统失败: {str(e)}[/bold red]")
        sys.exit(1)
    
    # 加载插件
    try:
        plugin_manager.discover_plugins('cdn_check.plugins')
    except Exception as e:
        console.print(f"[bold red]加载插件失败: {str(e)}[/bold red]")
        sys.exit(1)

@cli.command()
@click.argument('target')
@click.option('--output', '-o', help='输出文件路径')
@click.option('--format', '-f', type=click.Choice(['json', 'text']), default='text', help='输出格式')
@click.option('--simple', '-s', is_flag=True, help='简化输出，不显示详细信息')
@click.option('--plugin', '-p', help='指定要使用的插件')
@click.option('--config', help='指定配置文件')
@click.pass_context
def check(ctx, target: str, output: Optional[str], format: str, simple: bool, plugin: Optional[str], config: Optional[str]):
    """检测单个目标是否使用CDN"""
    app_instance = CDNCheckApp(config or ctx.obj['config'])
    
    result = None
    
    # 如果指定了特定插件，则只执行该插件
    if plugin:
        plugin_manager_instance = plugin_manager
        if plugin == "cdn_detector" and not target.startswith("{"):
            # 特殊处理CDN检测器，提供域名
            data = {"domain": target}
            plugin_instance = plugin_manager_instance.get_plugin(plugin)
            if plugin_instance:
                result = plugin_instance.execute(data)
            else:
                console.print(f"[bold red]插件'{plugin}'不存在[/bold red]")
                return
        else:
            if target.startswith("{"):
                try:
                    data = json.loads(target)
                except json.JSONDecodeError:
                    console.print("[bold red]无效的JSON数据[/bold red]")
                    return
            else:
                data = {"domain": target}
            
            plugin_instance = plugin_manager_instance.get_plugin(plugin)
            if plugin_instance:
                result = plugin_instance.execute(data)
            else:
                console.print(f"[bold red]插件'{plugin}'不存在[/bold red]")
                return
    else:
        # 执行所有检测
        with Progress() as progress:
            task = progress.add_task("[cyan]检测中...", total=1)
            
            # 执行检测
            result = asyncio.run(app_instance.check_target(target))
            
            progress.update(task, advance=1)
    
    # 保存最后的检测结果，供feedback命令使用
    _save_last_detection_result(result, target)
    
    # 输出结果处理
    if format == 'json':
        if output:
            with open(output, 'w', encoding='utf-8') as f:
                json.dump(result, f, indent=2, ensure_ascii=False)
        else:
            console.print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        # 文本格式输出
        if result and 'success' in result and result['success']:
            # 1. 输出最终结果
            if 'is_cdn' in result and result['is_cdn']:
                console.print(Panel(f"[bold green]目标 {result['target']} 使用了CDN服务[/bold green]"))
                console.print(f"CDN提供商: [bold cyan]{result.get('cdn_provider') or '未知'}[/bold cyan]")
                console.print(f"置信度: [bold cyan]{result.get('confidence')}%[/bold cyan]")
            else:
                console.print(Panel(f"[bold yellow]目标 {result['target']} 未使用CDN服务[/bold yellow]"))
            
            # 如果不是简化输出，显示详细信息
            if not simple and 'details' in result:
                # 2. 显示命中的CDN条件
                console.print(Rule("[bold]命中条件[/bold]"))
                
                if 'is_cdn' in result and result['is_cdn'] and 'indicators' in result:
                    indicators = result.get('indicators', [])
                    if isinstance(indicators, list):
                        for indicator in indicators:
                            console.print(f"[green]✓[/green] {indicator}")
                    elif isinstance(indicators, dict):
                        for provider, provider_indicators in indicators.items():
                            console.print(f"[bold]提供商 {provider}:[/bold]")
                            for indicator in provider_indicators:
                                console.print(f"  [green]✓[/green] {indicator}")
                else:
                    console.print("[yellow]未检测到CDN特征[/yellow]")
                
                # 3. 显示原始检测数据
                console.print(Rule("[bold]原始检测数据[/bold]"))
                
                details = result['details']
                
                # DNS信息
                if 'dns' in details:
                    dns_info = details['dns']
                    dns_tree = Tree("[bold]DNS信息[/bold]")
                    
                    if 'ips' in dns_info and dns_info['ips']:
                        ip_branch = dns_tree.add("解析IP:")
                        for ip in dns_info.get('ips', []):
                            ip_branch.add(f"[cyan]{ip}[/cyan]")
                    
                    if 'cname_chain' in dns_info and dns_info['cname_chain']:
                        cname_branch = dns_tree.add("CNAME链:")
                        for cname in dns_info.get('cname_chain', []):
                            cname_branch.add(f"[cyan]{cname}[/cyan]")
                    
                    if 'a_records' in dns_info and dns_info['a_records']:
                        a_branch = dns_tree.add("A记录:")
                        for record in dns_info.get('a_records', []):
                            a_branch.add(f"[cyan]{record}[/cyan]")
                    
                    console.print(dns_tree)
                
                # HTTP信息
                if 'http' in details and details['http']:
                    http_info = details['http']
                    http_tree = Tree("[bold]HTTP信息[/bold]")
                    
                    if 'server' in http_info and http_info['server']:
                        http_tree.add(f"服务器: [cyan]{http_info['server']}[/cyan]")
                    
                    if 'status_code' in http_info:
                        http_tree.add(f"状态码: [cyan]{http_info['status_code']}[/cyan]")
                    
                    if 'headers' in http_info and http_info['headers']:
                        headers_branch = http_tree.add("HTTP头部:")
                        for name, value in http_info['headers'].items():
                            headers_branch.add(f"[cyan]{name}: {value}[/cyan]")
                    
                    if 'cdn_headers' in http_info and http_info['cdn_headers']:
                        cdn_headers_branch = http_tree.add("[bold]CDN相关头部:[/bold]")
                        for header in http_info['cdn_headers']:
                            cdn_headers_branch.add(f"[green]{header['name']}: {header['value']}[/green]")
                    
                    console.print(http_tree)
                
                # IP信息
                if 'ip' in details and details['ip']:
                    ip_info = details['ip']
                    ip_tree = Tree("[bold]IP信息[/bold]")
                    
                    for ip, ip_data in ip_info.items():
                        ip_branch = ip_tree.add(f"[bold]{ip}[/bold]")
                        
                        if isinstance(ip_data, dict): 
                            # 展示ASN信息
                            asn_value = ip_data.get('asn')
                            if asn_value:
                                # 如果ASN是字典，需要特殊处理
                                if isinstance(asn_value, dict):
                                    asn_number = asn_value.get('asn')
                                    org = asn_value.get('organization', '')
                                    if asn_number:
                                        ip_branch.add(f"ASN: [cyan]{asn_number}[/cyan]")
                                    if org:
                                        ip_branch.add(f"组织: [cyan]{org}[/cyan]")
                                else:
                                    ip_branch.add(f"ASN: [cyan]{asn_value}[/cyan]")
                            
                            # 展示组织信息（可能直接在ip_data中或嵌套在asn中）
                            org = ip_data.get('org', ip_data.get('organization', ''))
                            if org and isinstance(org, str):
                                ip_branch.add(f"组织: [cyan]{org}[/cyan]")
                            
                            # 展示国家信息
                            country = ip_data.get('country', '')
                            if country:
                                if isinstance(country, dict):
                                    country_name = country.get('name', '')
                                    if country_name:
                                        ip_branch.add(f"国家: [cyan]{country_name}[/cyan]")
                                else:
                                    ip_branch.add(f"国家: [cyan]{country}[/cyan]")
                            
                            # 展示城市信息
                            city = ip_data.get('city', '')
                            if city:
                                if isinstance(city, dict):
                                    city_name = city.get('name', '')
                                    if city_name:
                                        ip_branch.add(f"城市: [cyan]{city_name}[/cyan]")
                                else:
                                    ip_branch.add(f"城市: [cyan]{city}[/cyan]")
                            
                            # 是否CDN IP
                            is_cdn = ip_data.get('is_cdn', ip_data.get('is_cdn_ip', False))
                            ip_branch.add(f"是否CDN IP: [{'green' if is_cdn else 'yellow'}]{is_cdn}[/{'green' if is_cdn else 'yellow'}]")
                            
                            # 如果有CDN提供商信息
                            cdn_provider = ip_data.get('cdn_provider')
                            if cdn_provider:
                                ip_branch.add(f"CDN提供商: [green]{cdn_provider}[/green]")
                    
                    console.print(ip_tree)
                
                # 证书信息
                if 'cert' in details and details['cert']:
                    cert_info = details['cert']
                    cert_tree = Tree("[bold]证书信息[/bold]")
                    
                    if 'subject' in cert_info:
                        subject_branch = cert_tree.add("主题:")
                        if isinstance(cert_info['subject'], dict):
                            for key, value in cert_info['subject'].items():
                                subject_branch.add(f"[cyan]{key}: {value}[/cyan]")
                        else:
                            subject_branch.add(f"[cyan]{cert_info['subject']}[/cyan]")
                    
                    if 'issuer' in cert_info:
                        issuer_branch = cert_tree.add("颁发者:")
                        if isinstance(cert_info['issuer'], dict):
                            for key, value in cert_info['issuer'].items():
                                issuer_branch.add(f"[cyan]{key}: {value}[/cyan]")
                        else:
                            issuer_branch.add(f"[cyan]{cert_info['issuer']}[/cyan]")
                    
                    # 支持多种可能的SAN键名
                    san_keys = ['sans', 'san', 'subjectAltName']
                    for key in san_keys:
                        if key in cert_info and cert_info[key]:
                            sans_branch = cert_tree.add("备用名称:")
                            for san in cert_info[key]:
                                sans_branch.add(f"[cyan]{san}[/cyan]")
                            break
                    
                    # 支持多种可能的有效期键名
                    if 'validity' in cert_info and isinstance(cert_info['validity'], dict):
                        validity_branch = cert_tree.add("有效期:")
                        validity_branch.add(f"[cyan]从: {cert_info['validity'].get('not_before', '未知')}[/cyan]")
                        validity_branch.add(f"[cyan]至: {cert_info['validity'].get('not_after', '未知')}[/cyan]")
                    elif all(k in cert_info for k in ['notBefore', 'notAfter']):
                        validity_branch = cert_tree.add("有效期:")
                        validity_branch.add(f"[cyan]从: {cert_info['notBefore']}[/cyan]")
                        validity_branch.add(f"[cyan]至: {cert_info['notAfter']}[/cyan]")
                    
                    console.print(cert_tree)
        # 如果是CDN检测插件的直接结果
        elif result and 'plugin' in result and result['plugin'] == 'cdn_detector':
            if 'result' in result and result['result']:
                cdn_result = result['result']
                is_cdn = cdn_result.get('is_cdn', False)
                
                if is_cdn:
                    cdn_provider = cdn_result.get('cdn_provider', '未知')
                    confidence = cdn_result.get('confidence', 0)
                    indicators = cdn_result.get('indicators', [])
                    
                    console.print(f"[bold green]目标使用了CDN服务[/bold green]")
                    console.print(f"CDN提供商: [bold]{cdn_provider}[/bold] (置信度: {confidence:.2f}%)")
                    
                    if indicators:
                        console.print("\n[bold]检测到的CDN特征:[/bold]")
                        for indicator in indicators:
                            console.print(f"• {indicator}")
                else:
                    console.print(f"[bold red]目标未使用CDN服务[/bold red]")
            else:
                console.print("[bold red]检测失败或无结果[/bold red]")
        else:
            console.print(Panel(f"[bold red]检测失败: {result.get('error', '未知错误')}[/bold red]"))
        
        # 如果需要输出到文件
        if output:
            with open(output, 'w', encoding='utf-8') as f:
                if result['success']:
                    if result['is_cdn']:
                        f.write(f"目标 {result['target']} 使用了CDN服务\n")
                        f.write(f"CDN提供商: {result['cdn_provider'] or '未知'}\n")
                        f.write(f"置信度: {result['confidence']}%\n")
                    else:
                        f.write(f"目标 {result['target']} 未使用CDN服务\n")
                    
                    # 详细信息
                    if not simple:
                        f.write("\n== 命中条件 ==\n")
                        if result['is_cdn'] and 'indicators' in result:
                            indicators = result.get('indicators', [])
                            if isinstance(indicators, list):
                                for indicator in indicators:
                                    f.write(f"✓ {indicator}\n")
                            elif isinstance(indicators, dict):
                                for provider, provider_indicators in indicators.items():
                                    f.write(f"\n提供商 {provider}:\n")
                                    for indicator in provider_indicators:
                                        f.write(f"  ✓ {indicator}\n")
                        else:
                            f.write("未检测到CDN特征\n")
                            
                        f.write("\n== 原始检测数据 ==\n")
                        # DNS信息
                        if 'dns' in result['details']:
                            dns_info = result['details']['dns']
                            f.write("\nDNS信息:\n")
                            
                            if 'ips' in dns_info and dns_info['ips']:
                                f.write(f"解析IP: {', '.join(dns_info.get('ips', []))}\n")
                            
                            if 'cname_chain' in dns_info and dns_info['cname_chain']:
                                f.write(f"CNAME链: {' -> '.join(dns_info.get('cname_chain', []))}\n")
                            
                            if 'a_records' in dns_info and dns_info['a_records']:
                                f.write(f"A记录: {', '.join(dns_info.get('a_records', []))}\n")
                        
                        # HTTP信息
                        if 'http' in result['details'] and result['details']['http']:
                            http_info = result['details']['http']
                            f.write("\nHTTP信息:\n")
                            
                            if 'server' in http_info and http_info['server']:
                                f.write(f"服务器: {http_info['server']}\n")
                            
                            if 'status_code' in http_info:
                                f.write(f"状态码: {http_info['status_code']}\n")
                            
                            if 'headers' in http_info and http_info['headers']:
                                f.write("HTTP头部:\n")
                                for name, value in http_info['headers'].items():
                                    f.write(f"  {name}: {value}\n")
                            
                            if 'cdn_headers' in http_info and http_info['cdn_headers']:
                                f.write("CDN相关头部:\n")
                                for header in http_info['cdn_headers']:
                                    f.write(f"  {header['name']}: {header['value']}\n")
                        
                        # IP信息
                        if 'ip' in result['details'] and result['details']['ip']:
                            ip_info = result['details']['ip']
                            f.write("\nIP信息:\n")
                            
                            for ip, ip_data in ip_info.items():
                                f.write(f"{ip}:\n")
                                
                                if isinstance(ip_data, dict): 
                                    # 展示ASN信息
                                    asn_value = ip_data.get('asn')
                                    if asn_value:
                                        # 如果ASN是字典，需要特殊处理
                                        if isinstance(asn_value, dict):
                                            asn_number = asn_value.get('asn')
                                            org = asn_value.get('organization', '')
                                            if asn_number:
                                                f.write(f"  ASN: {asn_number}\n")
                                            if org:
                                                f.write(f"  组织: {org}\n")
                                        else:
                                            f.write(f"  ASN: {asn_value}\n")
                                    
                                    # 展示组织信息（可能直接在ip_data中或嵌套在asn中）
                                    org = ip_data.get('org', ip_data.get('organization', ''))
                                    if org and isinstance(org, str):
                                        f.write(f"  组织: {org}\n")
                                    
                                    # 展示国家信息
                                    country = ip_data.get('country', '')
                                    if country:
                                        if isinstance(country, dict):
                                            country_name = country.get('name', '')
                                            if country_name:
                                                f.write(f"  国家: {country_name}\n")
                                        else:
                                            f.write(f"  国家: {country}\n")
                                    
                                    # 展示城市信息
                                    city = ip_data.get('city', '')
                                    if city:
                                        if isinstance(city, dict):
                                            city_name = city.get('name', '')
                                            if city_name:
                                                f.write(f"  城市: {city_name}\n")
                                        else:
                                            f.write(f"  城市: {city}\n")
                                    
                                    # 是否CDN IP
                                    is_cdn = ip_data.get('is_cdn', ip_data.get('is_cdn_ip', False))
                                    f.write(f"  是否CDN IP: {is_cdn}\n")
                                    
                                    # 如果有CDN提供商信息
                                    cdn_provider = ip_data.get('cdn_provider')
                                    if cdn_provider:
                                        f.write(f"  CDN提供商: {cdn_provider}\n")
                else:
                    f.write(f"检测失败: {result.get('error', '未知错误')}\n")

@cli.command()
@click.argument('file', type=click.Path(exists=True))
@click.option('--output', '-o', help='输出文件路径')
@click.option('--format', '-f', type=click.Choice(['json', 'text']), default='text', help='输出格式')
@click.option('--concurrency', '-n', type=int, default=10, help='并发数')
@click.pass_context
def batch(ctx, file: str, output: Optional[str], format: str, concurrency: int):
    """批量检测多个目标"""
    app = CDNCheckApp(ctx.obj['config'])
    
    # 读取目标列表
    with open(file, 'r', encoding='utf-8') as f:
        targets = [line.strip() for line in f.readlines() if line.strip() and not line.strip().startswith('#')]
    
    console.print(f"从 [cyan]{file}[/cyan] 读取了 [cyan]{len(targets)}[/cyan] 个目标")
    
    results = []
    
    with Progress() as progress:
        total = len(targets)
        task = progress.add_task("[cyan]检测中...", total=total)
        
        # 执行批量检测
        batch_results = asyncio.run(app.check_targets(targets))
        
        # 更新进度条
        progress.update(task, completed=total)
    
    # 处理结果
    for result in batch_results:
        print(f"检测结果: {result['target']} - {result['success']}")
        results.append(result)
    
    # 统计结果
    total = len(results)
    success = sum(1 for r in results if r['success'])
    failed = total - success
    cdn_count = sum(1 for r in results if r['success'] and r['is_cdn'])
    
    # 输出结果
    if format == 'json':
        if output:
            with open(output, 'w', encoding='utf-8') as f:
                json.dump(results, f, indent=2, ensure_ascii=False)
        else:
            console.print(json.dumps(results, indent=2, ensure_ascii=False))
    else:
        console.print(f"\n总计: [cyan]{total}[/cyan] 个目标")
        console.print(f"成功: [green]{success}[/green]")
        console.print(f"失败: [red]{failed}[/red]")
        console.print(f"使用CDN: [cyan]{cdn_count}[/cyan] ({cdn_count/total*100:.1f}%)")
        
        # 创建表格
        table = Table(show_header=True, header_style="bold")
        table.add_column("目标")
        table.add_column("状态")
        table.add_column("CDN")
        table.add_column("提供商")
        table.add_column("置信度")
        
        for result in results:
            target = result['target']
            status = "[green]成功[/green]" if result['success'] else f"[red]失败: {result.get('error', '未知错误')}[/red]"
            
            if result['success']:
                is_cdn = "[green]是[/green]" if result['is_cdn'] else "[yellow]否[/yellow]"
                provider = result['cdn_provider'] if result['is_cdn'] and result['cdn_provider'] else "-"
                confidence = f"{result['confidence']}%" if result['is_cdn'] else "-"
            else:
                is_cdn = "-"
                provider = "-"
                confidence = "-"
            
            table.add_row(target, status, is_cdn, ','.join(provider), confidence)
        
        console.print(table)
        
        # 如果需要输出到文件
        if output:
            with open(output, 'w', encoding='utf-8') as f:
                f.write(f"总计: {total} 个目标\n")
                f.write(f"成功: {success}\n")
                f.write(f"失败: {failed}\n")
                f.write(f"使用CDN: {cdn_count} ({cdn_count/total*100:.1f}%)\n\n")
                
                f.write("目标,状态,CDN,提供商,置信度\n")
                for result in results:
                    target = result['target']
                    status = "成功" if result['success'] else f"失败: {result.get('error', '未知错误')}"
                    
                    if result['success']:
                        is_cdn = "是" if result['is_cdn'] else "否"
                        provider = result['cdn_provider'] if result['is_cdn'] and result['cdn_provider'] else "-"
                        confidence = f"{result['confidence']}%" if result['is_cdn'] else "-"
                    else:
                        is_cdn = "-"
                        provider = "-"
                        confidence = "-"
                    
                    f.write(f"{target},{status},{is_cdn},{provider},{confidence}\n")

@cli.command()
def plugins():
    """列出所有可用插件"""
    console.print("[bold]已加载的插件:[/bold]")
    
    table = Table(show_header=True)
    table.add_column("插件名称")
    table.add_column("类型")
    table.add_column("描述")
    table.add_column("版本")
    
    for plugin_name, plugin in plugin_manager.get_plugins().items():
        table.add_row(
            plugin.plugin_name,
            plugin.plugin_type,
            plugin.plugin_description,
            plugin.plugin_version
        )
    
    console.print(table)

@cli.command()
@click.argument('plugin_name')
@click.argument('target')
@click.option('--format', '-f', type=click.Choice(['json', 'text']), default='text', help='输出格式')
@click.pass_context
def test_plugin(ctx, plugin_name, target, format):
    """测试单个插件的功能
    
    示例:
    python cli.py test_plugin ip_analyzer 104.21.48.1
    python cli.py test_plugin dns_resolver example.com
    python cli.py test_plugin http_requester https://example.com
    python cli.py test_plugin cert_analyzer example.com
    """
    # 简单判断是否是IP地址
    def is_ip(s):
        import re
        return bool(re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', s))
    
    # 获取插件
    plugin = plugin_manager.get_plugin(plugin_name)
    if not plugin:
        console.print(f"[bold red]错误: 插件 {plugin_name} 不存在[/bold red]")
        sys.exit(1)
    
    console.print(f"[bold]正在测试插件:[/bold] {plugin.plugin_name} ({plugin.plugin_description})")
    
    try:
        # 对于一些特殊插件，可能需要特殊处理目标参数
        if plugin_name == "cdn_detector" and not target.startswith("{"):
            # CDN检测器需要一个JSON结构，如果用户没有提供，就简单构造一个
            target = json.dumps({"domain": target, "ips": [target] if is_ip(target) else []})
        
        # 执行插件
        result = plugin.execute(target)
        
        # 输出结果
        if format == 'json':
            console.print(json.dumps(result, indent=2, ensure_ascii=False))
        else:
            # 文本格式输出
            console.print(Panel(f"[bold]测试结果[/bold]"))
            console.print(f"插件名称: [cyan]{plugin.plugin_name}[/cyan]")
            console.print(f"测试目标: [cyan]{target}[/cyan]")
            console.print(f"测试结果: [{'green' if result.get('success', False) else 'red'}]{result.get('success', False)}[/{'green' if result.get('success', False) else 'red'}]")
            
            if 'error' in result:
                console.print(f"错误信息: [red]{result['error']}[/red]")
            
            # 显示详细结果
            console.print(Rule("[bold]详细数据[/bold]"))
            
            # 移除一些不需要显示的字段
            display_result = result.copy()
            if 'plugin' in display_result:
                del display_result['plugin']
            if 'success' in display_result:
                del display_result['success']
            if 'error' in display_result:
                del display_result['error']
            if 'target' in display_result:
                del display_result['target']
            
            # 使用Pretty显示数据
            console.print(Pretty(display_result))
            
    except Exception as e:
        console.print(f"[bold red]测试过程中出错: {str(e)}[/bold red]")
        import traceback
        console.print(traceback.format_exc())
        sys.exit(1)

@cli.command()
@click.option("--correct/--incorrect", default=True, help="检测结果是否正确")
@click.option("--provider", help="实际的CDN提供商（如果已知）")
def feedback(correct, provider):
    """为最近的CDN检测结果提供反馈"""
    # 加载最近的检测结果
    last_result, last_domain = _load_last_detection_result()
    
    if not last_result:
        console = Console()
        console.print("[bold red]没有可反馈的检测结果，请先运行check命令[/bold red]")
        return
    
    # 获取CDN检测插件
    cdn_plugin = plugin_manager.get_plugin("cdn_detector")
    
    if not cdn_plugin:
        console = Console()
        console.print("[bold red]无法获取CDN检测插件[/bold red]")
        return
    
    # 提供反馈
    cdn_plugin.provide_feedback(correct, provider)
    
    console = Console()
    if correct:
        console.print(f"[bold green]已提交反馈: 域名 {last_domain} 的检测结果正确[/bold green]")
    else:
        provider_text = f"，实际提供商: {provider}" if provider else ""
        console.print(f"[bold yellow]已提交反馈: 域名 {last_domain} 的检测结果不正确{provider_text}[/bold yellow]")

@cli.command()
@click.option("--limit", "-l", type=int, default=10, help="显示结果数量限制")
@click.option("--all", "-a", is_flag=True, help="显示所有结果，默认只显示最近10条")
@click.option("--with-feedback", "-f", is_flag=True, help="只显示有用户反馈的结果")
def history(limit, all, with_feedback):
    """查看历史检测记录"""
    db = DBManager()
    
    if all:
        limit = 1000  # 设置一个较大的限制值
    
    sessions = db.get_all_sessions(limit=limit, with_feedback_only=with_feedback)
    
    if not sessions:
        console.print("[bold red]没有历史检测记录[/bold red]")
        return
    
    table = Table(title="CDN检测历史记录")
    table.add_column("ID", style="cyan")
    table.add_column("目标", style="green")
    table.add_column("时间", style="blue")
    table.add_column("结果", style="magenta")
    table.add_column("提供商", style="yellow")
    table.add_column("置信度", style="cyan")
    table.add_column("用户反馈", style="green")
    
    for session in sessions:
        session_id = str(session['id'])
        target = session['target']
        timestamp = session['timestamp']
        is_cdn = "是" if session['is_cdn'] else "否"
        cdn_provider = session['cdn_provider'] or "未知"
        confidence = f"{session['confidence']}%" if session['confidence'] else "N/A"
        
        feedback = "N/A"
        if session['user_feedback'] is not None:
            if session['user_feedback']:
                feedback = "[green]正确[/green]"
            else:
                actual = f" (实际: {session['actual_provider']})" if session['actual_provider'] else ""
                feedback = f"[red]不正确{actual}[/red]"
        
        table.add_row(session_id, target, timestamp, is_cdn, cdn_provider, confidence, feedback)
    
    console.print(table)

@cli.command()
@click.argument("session_id", type=int)
def detail(session_id):
    """查看特定检测会话的详细信息"""
    db = DBManager()
    
    # 获取会话信息
    session = db.get_detection_session(session_id)
    if not session:
        console.print(f"[bold red]未找到ID为 {session_id} 的检测记录[/bold red]")
        return
    
    # 获取指标信息
    indicators = db.get_session_indicators(session_id)
    
    # 获取IP信息
    ip_info = db.get_session_ip_info(session_id)
    
    # 显示会话信息
    console.print(Panel(f"[bold]检测会话 #{session_id}[/bold]"))
    console.print(f"目标: [bold green]{session['target']}[/bold green]")
    console.print(f"检测时间: [bold blue]{session['timestamp']}[/bold blue]")
    console.print(f"是否使用CDN: [bold {'green' if session['is_cdn'] else 'red'}]{('是' if session['is_cdn'] else '否')}[/bold {'green' if session['is_cdn'] else 'red'}]")
    
    if session['is_cdn']:
        console.print(f"CDN提供商: [bold yellow]{session['cdn_provider'] or '未知'}[/bold yellow]")
        console.print(f"置信度: [bold cyan]{session['confidence']}%[/bold cyan]")
    
    if session['user_feedback'] is not None:
        if session['user_feedback']:
            console.print("[bold green]用户反馈: 正确[/bold green]")
        else:
            actual = f"，实际提供商: {session['actual_provider']}" if session['actual_provider'] else ""
            console.print(f"[bold red]用户反馈: 不正确{actual}[/bold red]")
    
    # 显示检测指标
    if indicators:
        console.print(Rule("[bold]检测指标[/bold]"))
        for indicator in indicators:
            console.print(f"• {indicator['indicator']}")
    
    # 显示IP信息
    if ip_info:
        console.print(Rule("[bold]IP信息[/bold]"))
        for ip in ip_info:
            ip_type = "[bold green]CDN IP[/bold green]" if ip['is_cdn_ip'] else "[bold red]非CDN IP[/bold red]"
            console.print(f"• {ip['ip']} - {ip_type}")
            if ip['organization']:
                console.print(f"  组织: {ip['organization']}")
            if ip['country'] or ip['city']:
                location = f"{ip['country']} {ip['city']}".strip()
                console.print(f"  位置: {location}")
            if ip['asn']:
                console.print(f"  ASN: {ip['asn']}")

@cli.command()
@click.argument("output_file", type=click.Path())
@click.option("--format", "-f", type=click.Choice(['csv', 'json']), default='csv', help="输出格式")
@click.option("--limit", "-l", type=int, default=1000, help="导出数量限制")
@click.option("--with-feedback-only", "-w", is_flag=True, help="只导出有用户反馈的结果")
def export(output_file, format, limit, with_feedback_only):
    """导出检测历史数据"""
    db = DBManager()
    
    # 获取会话数据
    sessions = db.get_all_sessions(limit=limit, with_feedback_only=with_feedback_only)
    
    if not sessions:
        console.print("[bold red]没有可导出的检测记录[/bold red]")
        return
    
    try:
        if format == 'csv':
            # CSV格式导出
            with open(output_file, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                # 写入表头
                writer.writerow([
                    'ID', '目标', '时间', '是否CDN', 'CDN提供商', 
                    '置信度', '用户反馈', '实际提供商', '反馈时间'
                ])
                
                # 写入数据
                for session in sessions:
                    writer.writerow([
                        session['id'],
                        session['target'],
                        session['timestamp'],
                        session['is_cdn'],
                        session['cdn_provider'] or '',
                        session['confidence'],
                        '正确' if session['user_feedback'] else '不正确' if session['user_feedback'] is not None else '',
                        session['actual_provider'] or '',
                        session['feedback_timestamp'] or ''
                    ])
        else:
            # JSON格式导出
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(sessions, f, indent=2, ensure_ascii=False)
        
        console.print(f"[bold green]成功导出 {len(sessions)} 条记录到 {output_file}[/bold green]")
    except Exception as e:
        console.print(f"[bold red]导出数据失败: {str(e)}[/bold red]")

@cli.command()
def stats():
    """显示检测统计信息"""
    db = DBManager()
    
    # 获取会话总数
    sessions = db.get_all_sessions(limit=1)
    total_count = len(db.get_all_sessions(limit=100000))
    feedback_count = len(db.get_all_sessions(limit=100000, with_feedback_only=True))
    
    # 获取特征准确率统计
    feature_stats = db.get_feature_accuracy()
    
    console.print(Panel("[bold]CDN检测统计信息[/bold]"))
    console.print(f"总检测次数: [bold cyan]{total_count}[/bold cyan]")
    console.print(f"有用户反馈的次数: [bold cyan]{feedback_count}[/bold cyan]")
    
    if feature_stats:
        console.print(Rule("[bold]特征准确率统计[/bold]"))
        
        table = Table()
        table.add_column("特征类型", style="green")
        table.add_column("命中次数", style="cyan")
        table.add_column("正确次数", style="cyan")
        table.add_column("准确率", style="cyan")
        
        for feature, stats in feature_stats.items():
            accuracy = f"{stats['accuracy'] * 100:.2f}%"
            table.add_row(
                feature, 
                str(stats['total']), 
                str(stats['correct']), 
                accuracy
            )
        
        console.print(table)

if __name__ == '__main__':
    cli() 