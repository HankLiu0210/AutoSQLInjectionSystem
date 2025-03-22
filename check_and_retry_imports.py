# app/services/check_and_retry_imports.py

import sys
import os
import json
from datetime import datetime
from tqdm import tqdm

# 添加项目根目录到Python路径
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
sys.path.append(project_root)

from app import create_app, db
from app.models import CVE

def extract_cwe_ids(problem_types):
    """从problemTypes中提取CWE ID列表"""
    cwe_ids = []
    if problem_types:
        for pt in problem_types:
            if pt.get('descriptions'):
                for desc in pt['descriptions']:
                    if desc.get('type') == 'CWE' and desc.get('cweId'):
                        cwe_ids.append(desc['cweId'])
    return cwe_ids

def extract_cve_info(data, filename):
    """从JSON数据中提取CVE信息"""
    try:
        # 提取基本信息（CVE ID和发布日期）
        cve_info = {
            'cve_id': data['cveMetadata']['cveId'],
            'date_published': datetime.fromisoformat(data['cveMetadata']['datePublished'].replace('Z', '')),
        }

        # 提取描述信息
        try:
            cve_info['description'] = data['containers']['cna']['descriptions'][0]['value']
        except (KeyError, IndexError):
            cve_info['description'] = "No description available"

        # 提取CWE ID列表
        try:
            problem_types = data['containers']['cna'].get('problemTypes', [])
            cwe_ids = extract_cwe_ids(problem_types)
            cve_info['problem_type'] = json.dumps(cwe_ids) if cwe_ids else json.dumps([])
        except (KeyError, IndexError):
            cve_info['problem_type'] = json.dumps([])

        # 提取受影响的产品信息
        try:
            cve_info['affected_products'] = json.dumps(data['containers']['cna'].get('affected', []))
        except KeyError:
            cve_info['affected_products'] = json.dumps([])

        # 提取CVSS评分信息
        try:
            metrics = data['containers']['cna'].get('metrics', [])
            if metrics:
                cvss_info = None
                for metric in metrics:
                    if 'cvssV4_0' in metric:
                        cvss_info = metric['cvssV4_0']
                        cve_info['cvss_version'] = 'v4.0'
                        break
                    elif 'cvssV3_1' in metric:
                        cvss_info = metric['cvssV3_1']
                        cve_info['cvss_version'] = 'v3.1'
                        break
                    elif 'cvssV3_0' in metric:
                        cvss_info = metric['cvssV3_0']
                        cve_info['cvss_version'] = 'v3.0'
                        break
                
                if cvss_info:
                    cve_info.update({
                        'cvss_base_score': cvss_info.get('baseScore'),
                        'cvss_severity': cvss_info.get('baseSeverity'),
                        'cvss_vector': cvss_info.get('vectorString')
                    })
                else:
                    cve_info.update({
                        'cvss_base_score': None,
                        'cvss_severity': None,
                        'cvss_vector': None
                    })
            else:
                cve_info.update({
                    'cvss_version': None,
                    'cvss_base_score': None,
                    'cvss_severity': None,
                    'cvss_vector': None
                })
        except Exception as e:
            print(f"Warning: Error extracting CVSS info for {filename}: {str(e)}")
            cve_info.update({
                'cvss_version': None,
                'cvss_base_score': None,
                'cvss_severity': None,
                'cvss_vector': None
            })

        # 提取参考资料
        try:
            references = data['containers']['cna'].get('references', [])
            cve_info['references'] = json.dumps([ref.get('url', '') for ref in references])
        except KeyError:
            cve_info['references'] = json.dumps([])

        # 设置漏洞类型和SQL注入标志
        cve_info['vulnerability_type'] = None
        cve_info['is_sql_injection'] = False

        # 检查是否为SQL注入漏洞
        description_lower = cve_info['description'].lower()
        if 'sql injection' in description_lower or 'sqli' in description_lower:
            cve_info['is_sql_injection'] = True
            cve_info['vulnerability_type'] = 'sql_injection'

        return cve_info
    except Exception as e:
        error_msg = f"处理文件 {filename} 时出错: {str(e)}\n"
        error_msg += f"数据内容: {json.dumps(data, indent=2)[:200]}..."
        raise Exception(error_msg)

def check_import_status(base_path):
    """检查CVE文件的导入状态"""
    app = create_app()
    
    with app.app_context():
        # 获取数据库中所有的CVE ID
        db_cves = {cve.cve_id for cve in CVE.query.all()}
        print(f"数据库中现有 CVE 记录数: {len(db_cves)}")
        
        # 统计信息
        stats = {
            'total_files': 0,
            'imported': 0,
            'failed': 0,
            'failed_files': []
        }
        
        print("开始检查导入状态...")
        
        # 遍历文件系统中的所有CVE文件
        cves_path = os.path.join(base_path, 'cves')
        for year in sorted(os.listdir(cves_path)):
            year_path = os.path.join(cves_path, year)
            if not os.path.isdir(year_path):
                continue
                
            for subdir in sorted(os.listdir(year_path)):
                subdir_path = os.path.join(year_path, subdir)
                if not os.path.isdir(subdir_path):
                    continue
                
                for filename in sorted(os.listdir(subdir_path)):
                    if not filename.endswith('.json'):
                        continue
                    
                    stats['total_files'] += 1
                    file_path = os.path.join(subdir_path, filename)
                    
                    try:
                        with open(file_path, 'r', encoding='utf-8') as f:
                            data = json.load(f)
                            cve_id = data['cveMetadata']['cveId']
                            
                            if cve_id in db_cves:
                                stats['imported'] += 1
                            else:
                                stats['failed'] += 1
                                stats['failed_files'].append({
                                    'file': os.path.join(year, subdir, filename),
                                    'cve_id': cve_id,
                                    'error': 'Not in database'
                                })
                    except Exception as e:
                        stats['failed'] += 1
                        stats['failed_files'].append({
                            'file': os.path.join(year, subdir, filename),
                            'error': str(e)
                        })
        
        # 输出统计信息
        print("\n导入状态统计:")
        print(f"总文件数: {stats['total_files']}")
        print(f"成功导入: {stats['imported']}")
        print(f"导入失败: {stats['failed']}")
        
        # 保存失败记录到文件
        output_file = os.path.join(project_root, 'data', 'import_failures.json')
        os.makedirs(os.path.dirname(output_file), exist_ok=True)
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump({
                'stats': {
                    'total_files': stats['total_files'],
                    'imported': stats['imported'],
                    'failed': stats['failed']
                },
                'failed_files': stats['failed_files']
            }, f, indent=2)
        
        print(f"\n详细的失败记录已保存到: {output_file}")
        return output_file

def retry_failed_imports(base_path):
    """重新尝试导入失败的文件"""
    app = create_app()
    
    with app.app_context():
        # 首先获取已导入的CVE ID
        existing_cves = {cve.cve_id for cve in CVE.query.all()}
        print(f"数据库中现有 CVE 记录数: {len(existing_cves)}")
        
        # 读取失败记录
        failures_file = os.path.join(project_root, 'data', 'import_failures.json')
        if not os.path.exists(failures_file):
            print("未找到失败记录文件，请先运行 check_import_status")
            return
            
        with open(failures_file, 'r', encoding='utf-8') as f:
            failures = json.load(f)
        
        failed_files = failures['failed_files']
        print(f"发现 {len(failed_files)} 个失败记录")
        
        stats = {
            'attempted': 0,
            'succeeded': 0,
            'failed': 0,
            'errors': []
        }
        
        # 处理每个失败的文件
        for failed in tqdm(failed_files, desc="重试导入进度"):
            file_path = os.path.join(base_path, 'cves', failed['file'])
            if not os.path.exists(file_path):
                stats['failed'] += 1
                stats['errors'].append(f"文件不存在: {file_path}")
                continue
                
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    cve_id = data['cveMetadata']['cveId']
                    
                    # 只处理未成功导入的文件
                    if cve_id not in existing_cves:
                        stats['attempted'] += 1
                        
                        # 处理没有datePublished的情况
                        if 'datePublished' not in data['cveMetadata']:
                            # 使用其他日期字段或设置默认值
                            data['cveMetadata']['datePublished'] = (
                                data['cveMetadata'].get('dateReserved') or 
                                data['cveMetadata'].get('dateUpdated') or 
                                '2000-01-01T00:00:00Z'
                            )
                        
                        cve_info = extract_cve_info(data, os.path.basename(file_path))
                        new_cve = CVE(**cve_info)
                        db.session.add(new_cve)
                        db.session.commit()
                        stats['succeeded'] += 1
                        
            except Exception as e:
                stats['failed'] += 1
                stats['errors'].append(f"文件 {failed['file']} 导入失败: {str(e)}")
                db.session.rollback()
        
        print("\n重试导入统计:")
        print(f"尝试导入: {stats['attempted']}")
        print(f"成功导入: {stats['succeeded']}")
        print(f"导入失败: {stats['failed']}")
        
        if stats['errors']:
            print("\n错误记录:")
            for error in stats['errors'][:10]:
                print(f"- {error}")
            if len(stats['errors']) > 10:
                print(f"... 还有 {len(stats['errors']) - 10} 个错误未显示")

def main():
    base_path = r"D:/Downloads/cvelistV5-main"  # 替换为你的实际路径
    
    print("1. 检查导入状态")
    print("2. 重试导入失败的文件")
    print("3. 全部执行")
    
    choice = input("请选择操作 (1/2/3): ")
    
    if choice == '1':
        check_import_status(base_path)
    elif choice == '2':
        retry_failed_imports(base_path)
    elif choice == '3':
        failures_file = check_import_status(base_path)
        if failures_file and os.path.exists(failures_file):
            retry_failed_imports(base_path)
    else:
        print("无效的选择")

if __name__ == '__main__':
    main()