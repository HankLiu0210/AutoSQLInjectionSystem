import sys
import os
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
sys.path.append(project_root)

import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from datetime import datetime
import warnings
warnings.filterwarnings('ignore')

from app import create_app, db
from app.models import CVE

class VulnerabilityAnalyzer:
    def __init__(self):
        self.app = create_app()
        self.output_dir = 'reports'
        os.makedirs(self.output_dir, exist_ok=True)
        
    def get_vulnerability_distribution(self):
        """获取漏洞类型分布"""
        with self.app.app_context():
            sql = """
            SELECT 
                vt.type_name as vulnerability_type,
                COUNT(c.id) as count,
                ROUND(COUNT(c.id) * 100.0 / (SELECT COUNT(*) FROM cves WHERE vulnerability_category IS NOT NULL), 2) as percentage
            FROM cves c
            JOIN vulnerability_types vt ON c.vulnerability_category = vt.category_id
            WHERE c.vulnerability_category IS NOT NULL
            GROUP BY vt.category_id, vt.type_name
            ORDER BY COUNT(c.id) DESC
            """
            df = pd.read_sql(sql, db.engine)
            
            # 生成饼图
            plt.figure(figsize=(12, 8))
            plt.pie(df['count'], labels=df['vulnerability_type'], autopct='%1.1f%%')
            plt.title('Vulnerability Type Distribution')
            plt.savefig(f'{self.output_dir}/vulnerability_distribution.png')
            plt.close()
    
            return df
    
    def get_yearly_trends(self):
        """获取年度趋势"""
        with self.app.app_context():
            sql = """
            SELECT 
                YEAR(c.date_published) as year,
                vt.type_name as vulnerability_type,
                COUNT(*) as count
            FROM cves c
            JOIN vulnerability_types vt ON c.vulnerability_category = vt.category_id
            WHERE c.vulnerability_category IS NOT NULL 
            GROUP BY YEAR(c.date_published), vt.category_id, vt.type_name
            ORDER BY YEAR(c.date_published), vt.type_name
            """
            df = pd.read_sql(sql, db.engine)
            
            # 生成趋势图
            plt.figure(figsize=(15, 8))
            for vuln_type in df['vulnerability_type'].unique():
                data = df[df['vulnerability_type'] == vuln_type]
                plt.plot(data['year'], data['count'], marker='o', label=vuln_type)
            
            plt.title('Yearly Vulnerability Trends')
            plt.xlabel('Year')
            plt.ylabel('Number of Vulnerabilities')
            plt.legend(bbox_to_anchor=(1.05, 1), loc='upper left')
            plt.tight_layout()
            plt.savefig(f'{self.output_dir}/yearly_trends.png')
            plt.close()
    
            return df
    
    def get_cvss_analysis(self):
        """CVSS评分分析"""
        with self.app.app_context():
            sql = """
            SELECT 
                vt.type_name as vulnerability_type,
                ROUND(AVG(c.cvss_base_score), 2) as avg_score,
                MIN(c.cvss_base_score) as min_score,
                MAX(c.cvss_base_score) as max_score,
                COUNT(*) as total
            FROM cves c
            JOIN vulnerability_types vt ON c.vulnerability_category = vt.category_id
            WHERE c.vulnerability_category IS NOT NULL 
            GROUP BY vt.category_id, vt.type_name
            ORDER BY AVG(c.cvss_base_score) DESC
            """
            df = pd.read_sql(sql, db.engine)
            
            # 生成条形图
            plt.figure(figsize=(12, 6))
            plt.bar(df['vulnerability_type'], df['avg_score'])
            plt.xticks(rotation=45, ha='right')
            plt.title('Average CVSS Score by Vulnerability Type')
            plt.xlabel('Vulnerability Type')
            plt.ylabel('Average CVSS Score')
            plt.tight_layout()
            plt.savefig(f'{self.output_dir}/cvss_analysis.png')
            plt.close()
    
            return df
    
    def generate_report(self):
        """生成完整报告"""
        # 获取所有分析结果
        distribution_df = self.get_vulnerability_distribution()
        trends_df = self.get_yearly_trends()
        cvss_df = self.get_cvss_analysis()
        
        # 生成HTML报告
        html_report = f"""
        <html>
        <head>
            <title>Vulnerability Analysis Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                h1 {{ color: #333; }}
                table {{ border-collapse: collapse; width: 100%; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                th {{ background-color: #f2f2f2; }}
                img {{ max-width: 100%; height: auto; }}
            </style>
        </head>
        <body>
            <h1>Vulnerability Analysis Report</h1>
            <h2>Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</h2>
            
            <h2>Vulnerability Distribution</h2>
            <img src="vulnerability_distribution.png">
            {distribution_df.to_html()}
            
            <h2>Yearly Trends</h2>
            <img src="yearly_trends.png">
            {trends_df.to_html()}
            
            <h2>CVSS Analysis</h2>
            <img src="cvss_analysis.png">
            {cvss_df.to_html()}
        </body>
        </html>
        """
        
        # 保存报告
        with open(f'{self.output_dir}/report.html', 'w', encoding='utf-8') as f:
            f.write(html_report)
        
        # 导出Excel
        with pd.ExcelWriter(f'{self.output_dir}/vulnerability_analysis.xlsx') as writer:
            distribution_df.to_excel(writer, sheet_name='Distribution', index=False)
            trends_df.to_excel(writer, sheet_name='Yearly Trends', index=False)
            cvss_df.to_excel(writer, sheet_name='CVSS Analysis', index=False)
if __name__ == '__main__':
    analyzer = VulnerabilityAnalyzer()
    analyzer.generate_report()
    print(f"Report generated in {analyzer.output_dir} directory")
