from flask import Blueprint, jsonify, request
from app import db
from app.models.cve import CVE, VulnerabilityType
from sqlalchemy import func

bp = Blueprint('api', __name__, url_prefix='/api')

@bp.route('/test', methods=['GET'])
def test():
    """测试API是否正常工作"""
    return jsonify({
        'message': 'API is working!',
        'status': 'success'
    })

from sqlalchemy import text  # 添加这行导入

@bp.route('/dashboard/stats', methods=['GET'])
def get_dashboard_stats():
    """获取仪表盘统计数据"""
    try:
        # 1. 获取总漏洞数
        total_vulnerabilities = CVE.query.count()
        print(f"Total vulnerabilities: {total_vulnerabilities}")  # 调试日志
        
        # 2. 获取漏洞类型统计
        type_stats_query = text("""
            SELECT 
                vt.category_id,
                vt.type_name,
                COUNT(c.id) as count,
                ROUND(COUNT(c.id) * 100.0 / (
                    SELECT COUNT(*) 
                    FROM cves 
                    WHERE vulnerability_category IS NOT NULL
                ), 2) as percentage
            FROM vulnerability_types vt
            LEFT JOIN cves c ON c.vulnerability_category = vt.category_id
            WHERE vt.category_id IS NOT NULL
            GROUP BY vt.category_id, vt.type_name
            ORDER BY count DESC
        """)
        
        # 3. [新增] 获取年度趋势统计
        trend_query = text("""
            SELECT 
                EXTRACT(YEAR FROM date_published) as year,
                COUNT(*) as total_count,
                SUM(CASE WHEN vulnerability_category = 1 THEN 1 ELSE 0 END) as sql_injection_count,
                SUM(CASE WHEN vulnerability_category = 2 THEN 1 ELSE 0 END) as xss_count,
                SUM(CASE WHEN vulnerability_category = 3 THEN 1 ELSE 0 END) as rce_count,
                SUM(CASE WHEN vulnerability_category = 4 THEN 1 ELSE 0 END) as buffer_overflow_count,
                SUM(CASE WHEN vulnerability_category = 5 THEN 1 ELSE 0 END) as path_traversal_count,
                SUM(CASE WHEN vulnerability_category = 6 THEN 1 ELSE 0 END) as dos_count,
                SUM(CASE WHEN vulnerability_category = 7 THEN 1 ELSE 0 END) as csrf_count,
                SUM(CASE WHEN vulnerability_category = 8 THEN 1 ELSE 0 END) as ssrf_count,
                SUM(CASE WHEN vulnerability_category = 9 THEN 1 ELSE 0 END) as xxe_count,
                SUM(CASE WHEN vulnerability_category = 10 THEN 1 ELSE 0 END) as file_upload_count
            FROM cves
            WHERE date_published IS NOT NULL
            GROUP BY EXTRACT(YEAR FROM date_published)
            ORDER BY year ASC
        """)
        
        # 4. [新增] 获取严重程度分布
        severity_query = text("""
            SELECT 
                CASE 
                    WHEN cvss_base_score IS NULL OR cvss_base_score = 0 THEN 'Unknown'
                    WHEN cvss_base_score >= 9.0 THEN 'Critical'
                    WHEN cvss_base_score >= 7.0 THEN 'High'
                    WHEN cvss_base_score >= 4.0 THEN 'Medium'
                    WHEN cvss_base_score >= 0.1 THEN 'Low'
                    ELSE 'Unknown'
                END as severity_level,
                COUNT(*) as count
            FROM cves
            WHERE cvss_base_score IS NOT NULL
            GROUP BY 
                CASE
                    WHEN cvss_base_score IS NULL OR cvss_base_score = 0 THEN 'Unknown'
                    WHEN cvss_base_score >= 9.0 THEN 'Critical'
                    WHEN cvss_base_score >= 7.0 THEN 'High'
                    WHEN cvss_base_score >= 4.0 THEN 'Medium'
                    WHEN cvss_base_score >= 0.1 THEN 'Low'
                    ELSE 'Unknown'
                END
            ORDER BY 
                CASE severity_level
                    WHEN 'Critical' THEN 1
                    WHEN 'High' THEN 2
                    WHEN 'Medium' THEN 3
                    WHEN 'Low' THEN 4
                    WHEN 'Unknown' THEN 5
                END
        """)

        # 执行查询并打印结果
        try:
            # 漏洞类型统计
            # type_result = db.session.execute(type_stats_query)
            type_result = db.session.execute(type_stats_query)
            trend_result = db.session.execute(trend_query)
            severity_result = db.session.execute(severity_query)

            vulnerability_types = []
            for row in type_result:
                vulnerability_types.append({
                    'category_id': row.category_id,
                    'type_name': row.type_name,
                    'count': int(row.count),
                    'percentage': float(row.percentage) if row.percentage else 0
                })
            print(f"Vulnerability types data: {vulnerability_types}")  # 调试日志

            # 趋势数据
            trend_result = db.session.execute(trend_query)
            trend_data = []
            for row in trend_result:
                trend_data.append({
                    # 'year': int(row.year),
                    # 'total_count': int(row.total_count),
                    # 'high_severity_count': int(row.high_severity_count)
                    'year': int(row.year),
                    'total_count': int(row.total_count),
                    'sql_injection_count': int(row.sql_injection_count),
                    'xss_count': int(row.xss_count),
                    'rce_count': int(row.rce_count),
                    'buffer_overflow_count': int(row.buffer_overflow_count),
                    'path_traversal_count': int(row.path_traversal_count),
                    'dos_count': int(row.dos_count),
                    'csrf_count': int(row.csrf_count),
                    'ssrf_count': int(row.ssrf_count),
                    'xxe_count': int(row.xxe_count),
                    'file_upload_count': int(row.file_upload_count)
                })
            print(f"Trend data: {trend_data}")  # 调试日志
            
            # 严重程度分布
            severity_result = db.session.execute(severity_query)
            severity_distribution = []
            for row in severity_result:
                severity_distribution.append({
                    'level': row.severity_level,
                    'count': int(row.count)
                })
            print(f"Severity distribution: {severity_distribution}")  # 调试日志

        except Exception as e:
            print(f"Query execution error: {str(e)}")
            return jsonify({'error': 'Query execution error', 'message': str(e)}), 500

        # 获取已分类漏洞总数
        categorized_count = CVE.query.filter(CVE.vulnerability_category.isnot(None)).count()
        
        # 构建响应数据
        response_data = {
            'total_vulnerabilities': total_vulnerabilities,
            'categorized_count': categorized_count,
            'vulnerability_types': vulnerability_types,
            'trend_data': trend_data,
            'severity_distribution': severity_distribution
        }
        
        print(f"Final response data: {response_data}")  # 调试日志
        return jsonify(response_data)

    except Exception as e:
        print(f"Error in get_dashboard_stats: {str(e)}")
        return jsonify({'error': 'Internal Server Error', 'message': str(e)}), 500


# 添加调试端点
@bp.route('/debug/vulnerability-types', methods=['GET'])
def debug_vulnerability_types():
    """调试端点：查看漏洞类型表的数据"""
    try:
        # 直接查询 vulnerability_types 表
        query = text("SELECT * FROM vulnerability_types")
        result = db.session.execute(query)
        types = []
        for row in result:
            types.append({
                'category_id': row.category_id,
                'type_name': row.type_name,
                'type_code': row.type_code if 'type_code' in row.keys() else None,
                'description': row.description if 'description' in row.keys() else None
            })
        return jsonify(types)
    except Exception as e:
        print(f"Debug endpoint error: {str(e)}")
        return jsonify({'error': str(e)}), 500
    
    
@bp.route('/cves', methods=['GET'])
def get_cves():
    """获取CVE列表，支持分页和筛选"""
    try:
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('pageSize', 20, type=int)
        vuln_type = request.args.get('type', type=int)
        keyword = request.args.get('keyword', '')
        
        query = CVE.query
        
        if vuln_type:
            query = query.filter(CVE.vulnerability_category == vuln_type)
        
        if keyword:
            query = query.filter(
                db.or_(
                    CVE.cve_id.ilike(f'%{keyword}%'),
                    CVE.description.ilike(f'%{keyword}%')
                )
            )
        
        pagination = query.order_by(CVE.date_published.desc())\
                        .paginate(page=page, per_page=per_page)
        
        return jsonify({
            'items': [item.to_dict() for item in pagination.items],
            'total': pagination.total,
            'page': page,
            'pageSize': per_page
        })
    except Exception as e:
        print(f"Error in get_cves: {str(e)}")
        return jsonify({'error': 'Internal Server Error', 'message': str(e)}), 500

@bp.route('/vulnerabilities', methods=['GET'])
def get_vulnerabilities():
    """获取漏洞列表，支持分页和筛选"""
    try:
        page = int(request.args.get('page', 1))
        per_page = int(request.args.get('per_page', 20))
        search = request.args.get('search', '')
        vuln_type = request.args.get('type')
        severity = request.args.get('severity')  # 新增严重程度参数
        
        query = CVE.query
        
        # 搜索过滤
        if search:
            query = query.filter(
                db.or_(
                    CVE.cve_id.ilike(f'%{search}%'),
                    CVE.description.ilike(f'%{search}%')
                )
            )
        
        # 类型过滤 - 修改这部分
        if vuln_type:
            try:
                type_id = int(vuln_type)
                # 打印分布类型
                type_distribution = db.session.query(
                    CVE.vulnerability_category,
                    func.count(CVE.id)
                ).group_by(CVE.vulnerability_category).all()
                print("Vulnerability category distribution:", type_distribution)

                
                # 打印将要执行的查询
                query = query.filter(CVE.vulnerability_category == type_id)
                print("SQL Query:", str(query))
            except ValueError:
                print(f"Invalid vulnerability type value: {vuln_type}")

        # 严重程度过滤
        if severity:
            severity_ranges = {
                'critical': (9.0, 10.0),
                'high': (7.0, 8.9),
                'medium': (4.0, 6.9),
                'low': (0.1, 3.9),
                'unknown': (0, 0)  # 对应 NULL 或 0
            }
            
            if severity in severity_ranges:
                if severity == 'unknown':
                    query = query.filter(
                        db.or_(
                            CVE.cvss_base_score == 0,
                            CVE.cvss_base_score.is_(None)
                        )
                    )
                else:
                    min_score, max_score = severity_ranges[severity]
                    query = query.filter(
                        CVE.cvss_base_score.between(min_score, max_score)
                    )

        # 获取总数
        total = query.count()
        
        # 分页
        pagination = query.order_by(CVE.date_published.desc())\
                        .paginate(page=page, per_page=per_page)
        
        # 添加调试输出
        print(f"Vulnerability type filter: {vuln_type}")
        print(f"Total results: {total}")
        
        return jsonify({
            'items': [item.to_dict() for item in pagination.items],
            'total': total
        })
        
    except Exception as e:
        print(f"Error in get_vulnerabilities: {str(e)}")
        return jsonify({'error': 'Internal Server Error', 'message': str(e)}), 500

@bp.route('/vulnerability-types', methods=['GET'])
def get_vulnerability_types():
    """获取所有漏洞类型"""
    try:
        types = VulnerabilityType.query.all()
        return jsonify([type.to_dict() for type in types])
    except Exception as e:
        print(f"Error in get_vulnerability_types: {str(e)}")
        return jsonify({'error': 'Internal Server Error', 'message': str(e)}), 500

@bp.route('/vulnerability/<cve_id>', methods=['GET'])
def get_vulnerability_details(cve_id):
    """获取单个漏洞的详细信息"""
    try:
        vulnerability = CVE.query.filter_by(cve_id=cve_id).first()
        
        if not vulnerability:
            return jsonify({'error': 'Vulnerability not found'}), 404
            
        return jsonify(vulnerability.to_dict(with_references=True))
        
    except Exception as e:
        print(f"Error in get_vulnerability_details: {str(e)}")
        return jsonify({'error': 'Internal Server Error', 'message': str(e)}), 500

# 错误处理
@bp.errorhandler(404)
def not_found_error(error):
    return jsonify({
        'error': 'Not Found',
        'message': 'The requested URL was not found on the server.'
    }), 404

@bp.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return jsonify({
        'error': 'Internal Server Error',
        'message': str(error)
    }), 500