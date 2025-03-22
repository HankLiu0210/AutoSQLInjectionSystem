from app import db
from datetime import datetime

class CVE(db.Model):
    """CVE漏洞信息模型"""
    __tablename__ = 'cves'

    id = db.Column(db.Integer, primary_key=True)
    cve_id = db.Column(db.String(20), unique=True, nullable=False)
    description = db.Column(db.Text)
    problem_type = db.Column(db.Text)
    affected_products = db.Column(db.Text)
    date_published = db.Column(db.DateTime)
    cvss_version = db.Column(db.String(10))
    cvss_base_score = db.Column(db.Float)
    cvss_severity = db.Column(db.String(20))
    cvss_vector = db.Column(db.String(512))
    vulnerability_type = db.Column(db.String(100))
    is_sql_injection = db.Column(db.Boolean)
    references = db.Column(db.Text)
    vulnerability_category = db.Column(db.Integer)  # 不添加外键约束

    def to_dict(self, with_references=False):
        """转换为字典格式，用于API响应"""
        data = {
            'id': self.id,
            'cve_id': self.cve_id,
            'description': self.description,
            'problem_type': self.problem_type,
            'affected_products': self.affected_products,
            'date_published': self.date_published.strftime('%Y-%m-%d %H:%M:%S') if self.date_published else None,
            'cvss_version': self.cvss_version,
            'cvss_base_score': self.cvss_base_score,
            'cvss_severity': self.cvss_severity,
            'cvss_vector': self.cvss_vector,
            'vulnerability_type': self.vulnerability_type,
            'is_sql_injection': self.is_sql_injection,
            'vulnerability_category': self.vulnerability_category
        }
        
        if with_references and self.references:
            try:
                data['references'] = self.references.split(',')
            except:
                data['references'] = []
                
        return data

class VulnerabilityType(db.Model):
    """漏洞类型模型"""
    __tablename__ = 'vulnerability_types'
    
    category_id = db.Column(db.Integer, primary_key=True)
    type_name = db.Column(db.String(50), nullable=False)
    type_code = db.Column(db.String(50))
    description = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        """转换为字典格式，用于API响应"""
        return {
            'category_id': self.category_id,
            'type_name': self.type_name,
            'type_code': self.type_code,
            'description': self.description,
            'created_at': self.created_at.strftime('%Y-%m-%d %H:%M:%S')
        }