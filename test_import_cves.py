import json
import os
from datetime import datetime
from app import create_app, db
from app.models import CVE
from tqdm import tqdm

def test_import_cves(base_path, max_files=5):
    """测试导入少量CVE数据"""
    app = create_app()
    
    with app.app_context():
        print("开始测试导入CVE数据...")
        stats = {
            'processed': 0,
            'imported': 0,
            'errors': []
        }
        
        cves_path = os.path.join(base_path, 'cves')
        # 只处理1999年的数据
        year_path = os.path.join(cves_path, '1999')
        if os.path.isdir(year_path):
            print(f"\n处理1999年的CVE示例...")
            
            # 只处理0xxx目录
            subdir_path = os.path.join(year_path, '0xxx')
            if os.path.isdir(subdir_path):
                # 获取前max_files个文件
                files = sorted([f for f in os.listdir(subdir_path) if f.endswith('.json')])[:max_files]
                
                for filename in files:
                    file_path = os.path.join(subdir_path, filename)
                    print(f"\n处理文件: {filename}")
                    
                    try:
                        with open(file_path, 'r', encoding='utf-8') as f:
                            data = json.load(f)
                        
                        # 提取CVE信息
                        cve_info = {
                            'cve_id': data['cveMetadata']['cveId'],
                            'state': data['cveMetadata']['state'],
                            'date_published': datetime.fromisoformat(data['cveMetadata']['datePublished'].replace('Z', '+00:00')),
                            'date_reserved': datetime.fromisoformat(data['cveMetadata']['dateReserved'].replace('Z', '+00:00')),
                            'date_updated': datetime.fromisoformat(data['cveMetadata']['dateUpdated'].replace('Z', '+00:00')),
                            'description': data['containers']['cna']['descriptions'][0]['value'],
                            'assigner_org_id': data['cveMetadata']['assignerOrgId'],
                            'assigner_short_name': data['cveMetadata']['assignerShortName'],
                            'affected_products': json.dumps(data['containers']['cna']['affected']),
                            'references': json.dumps([ref['url'] for ref in data['containers']['cna']['references']]),
                            'data_type': data['dataType'],
                            'data_version': data['dataVersion'],
                            'is_sql_injection': False
                        }
                        
                        # 检查是否已存在
                        existing = CVE.query.filter_by(cve_id=cve_info['cve_id']).first()
                        if existing:
                            print(f"更新现有记录: {cve_info['cve_id']}")
                            for key, value in cve_info.items():
                                setattr(existing, key, value)
                        else:
                            print(f"创建新记录: {cve_info['cve_id']}")
                            new_cve = CVE(**cve_info)
                            db.session.add(new_cve)
                        
                        db.session.commit()
                        stats['imported'] += 1
                        
                        # 打印一些关键信息
                        print(f"CVE ID: {cve_info['cve_id']}")
                        print(f"发布日期: {cve_info['date_published']}")
                        print(f"描述: {cve_info['description'][:200]}...")
                        print("-" * 80)
                        
                    except Exception as e:
                        db.session.rollback()
                        error_msg = f"处理文件 {filename} 时出错: {str(e)}"
                        print(f"错误: {error_msg}")
                        stats['errors'].append(error_msg)
                    
                    stats['processed'] += 1
        
        # 打印统计信息
        print("\n测试导入完成!")
        print(f"处理文件数: {stats['processed']}")
        print(f"成功导入数: {stats['imported']}")
        
        if stats['errors']:
            print("\n错误记录:")
            for error in stats['errors']:
                print(f"- {error}")
        
        # 验证导入的数据
        print("\n验证导入的数据:")
        imported_cves = CVE.query.all()
        print(f"数据库中的记录总数: {len(imported_cves)}")
        if imported_cves:
            print("\n示例记录:")
            for cve in imported_cves[:3]:  # 显示前3条记录
                print(f"\nCVE ID: {cve.cve_id}")
                print(f"描述: {cve.description[:200]}...")
                print(f"发布日期: {cve.date_published}")
                print("-" * 80)

if __name__ == '__main__':
    base_path = r"C:/Projects/AutoSQLInjectionSystem/cvelistV5-main"
    test_import_cves(base_path, max_files=5)  # 只处理5个文件