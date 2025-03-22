# 导入必要的模块
import json
import os
from datetime import datetime
from app import create_app, db
from app.models import CVE
from tqdm import tqdm

def count_total_files(base_path):
    """计算需要处理的文件总数"""
    total = 0
    cves_path = os.path.join(base_path, 'cves')
    for year in os.listdir(cves_path):
        year_path = os.path.join(cves_path, year)
        if not os.path.isdir(year_path):
            continue
        for subdir in os.listdir(year_path):
            subdir_path = os.path.join(year_path, subdir)
            if not os.path.isdir(subdir_path):
                continue
            total += len([f for f in os.listdir(subdir_path) if f.endswith('.json')])
    return total

def extract_cwe_ids(problem_types):
    """从problemTypes中提取CWE ID列表
    Args:
        problem_types: problemTypes数据列表
    Returns:
        list: CWE ID列表，如果没有CWE则返回空列表
    """
    cwe_ids = []
    if problem_types:  # 确保problem_types不为None
        for pt in problem_types:
            if pt.get('descriptions'):
                for desc in pt['descriptions']:
                    if desc.get('type') == 'CWE' and desc.get('cweId'):
                        cwe_ids.append(desc['cweId'])
    
    return cwe_ids  # 如果没有找到CWE，返回空列表

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
            cve_info['problem_type'] = json.dumps(cwe_ids) if cwe_ids else json.dumps([])  # 如果没有CWE，存储空列表
        except (KeyError, IndexError):
            cve_info['problem_type'] = json.dumps([])  # 出错时也存储空列表

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

def import_cves(base_path):
    """导入CVE数据到数据库"""
    app = create_app()
    
    with app.app_context():
        total_files = count_total_files(base_path)
        print(f"找到 {total_files} 个CVE文件需要处理")
        
        stats = {
            'processed': 0,
            'imported': 0,
            'sql_injection': 0,
            'errors': []
        }
        
        pbar = tqdm(total=total_files, desc="导入进度")
        
        cves_path = os.path.join(base_path, 'cves')
        for year in sorted(os.listdir(cves_path)):
            year_path = os.path.join(cves_path, year)
            if not os.path.isdir(year_path):
                continue
            print(f"\n处理 {year} 年的数据...")
                
            for subdir in sorted(os.listdir(year_path)):
                subdir_path = os.path.join(year_path, subdir)
                if not os.path.isdir(subdir_path):
                    continue
                
                batch = []
                batch_size = 100
                
                for filename in sorted(os.listdir(subdir_path)):
                    if not filename.endswith('.json'):
                        continue
                        
                    file_path = os.path.join(subdir_path, filename)
                    try:
                        with open(file_path, 'r', encoding='utf-8') as f:
                            data = json.load(f)
                        
                        cve_info = extract_cve_info(data, filename)
                        if cve_info['is_sql_injection']:
                            stats['sql_injection'] += 1
                        
                        batch.append(cve_info)
                        stats['processed'] += 1
                        
                        if len(batch) >= batch_size:
                            try:
                                for info in batch:
                                    # 处理CVE记录
                                    existing_cve = CVE.query.filter_by(cve_id=info['cve_id']).first()
                                    if existing_cve:
                                        for key, value in info.items():
                                            setattr(existing_cve, key, value)
                                    else:
                                        new_cve = CVE(**info)
                                        db.session.add(new_cve)
                                
                                db.session.commit()
                                stats['imported'] += len(batch)
                                batch = []
                            except Exception as e:
                                db.session.rollback()
                                stats['errors'].append(f"批量提交错误: {str(e)}")
                        
                        pbar.update(1)
                        
                    except Exception as e:
                        stats['errors'].append(str(e))
                        pbar.update(1)
                        continue
                
                # 处理剩余的批次
                if batch:
                    try:
                        for info in batch:
                            existing_cve = CVE.query.filter_by(cve_id=info['cve_id']).first()
                            if existing_cve:
                                for key, value in info.items():
                                    setattr(existing_cve, key, value)
                            else:
                                new_cve = CVE(**info)
                                db.session.add(new_cve)
                        
                        db.session.commit()
                        stats['imported'] += len(batch)
                    except Exception as e:
                        db.session.rollback()
                        stats['errors'].append(f"最终批次提交错误: {str(e)}")
        
        pbar.close()
        print("\n导入完成!")
        print(f"处理文件总数: {stats['processed']}")
        print(f"成功导入CVE记录: {stats['imported']}")
        print(f"SQL注入漏洞数量: {stats['sql_injection']}")
        
        if stats['errors']:
            print("\n错误记录:")
            for error in stats['errors'][:10]:
                print(f"- {error}")
            if len(stats['errors']) > 10:
                print(f"... 还有 {len(stats['errors']) - 10} 个错误未显示")

if __name__ == '__main__':
    base_path = r"D:/Downloads/cvelistV5-main"
    import_cves(base_path)