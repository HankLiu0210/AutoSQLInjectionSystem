<template>
  <div class="cve-list">
    <el-container>
      <el-main>
        <!-- 页面标题和工具栏 -->
        <div class="page-header">
          <div class="title-section">
            <h2>CVE漏洞库</h2>
            <el-tag type="info">共 {{ total }} 条记录</el-tag>
          </div>
          
          <div class="toolbar">
            <!-- 搜索框 -->
            <el-input
              v-model="searchQuery"
              placeholder="搜索 CVE ID 或描述"
              class="search-input"
              clearable
              @keyup.enter="handleSearch"
            >
              <template #prefix>
                <el-icon><Search /></el-icon>
              </template>
            </el-input>
            
            <!-- 漏洞类型筛选 -->
            <el-select
              v-model="selectedType"
              placeholder="选择漏洞类型"
              clearable
              class="type-select"
              @change="handleSearch"
            >
              <el-option
                v-for="type in vulnerabilityTypes"
                :key="type.category_id"
                :label="`${type.type_name} (${typeNameMap[type.type_name]})`"
                :value="type.category_id"
              >
                <span class="type-option">
                  <span class="type-name">{{ type.type_name }}</span>
                  <span class="type-chinese">{{ typeNameMap[type.type_name] }}</span>
                </span>
              </el-option>
            </el-select>

            <!-- 严重程度筛选 -->
            <el-select
              v-model="selectedSeverity"
              placeholder="选择严重程度"
              clearable
              class="severity-select"
              @change="handleSearch"
            >
              <el-option
                v-for="severity in severityOptions"
                :key="severity.value"
                :label="severity.label"
                :value="severity.value"
              >
                <span class="severity-option">
                  <el-tag :type="getSeverityTagType(severity.value)" size="small">
                    {{ severity.label }}
                  </el-tag>
                </span>
              </el-option>
            </el-select>
          </div>
        </div>

        <!-- 漏洞列表 -->
        <el-card class="table-card" shadow="hover">
          <el-table
            v-loading="loading"
            :data="tableData"
            style="width: 100%"
            @row-click="showDetails"
            :header-cell-style="{ background: '#f5f7fa' }"
            border
          >
            <el-table-column prop="cve_id" label="CVE ID" width="180">
              <template #default="{ row }">
                <el-tag size="small">{{ row.cve_id }}</el-tag>
              </template>
            </el-table-column>            
            
            <el-table-column prop="vulnerability_type" label="漏洞类型" min-width="400">
              <template #default="{ row }">
                <el-tag 
                  :type="getTypeTagType(row.vulnerability_category)"
                  effect="light"
                >
                  {{ getVulnerabilityTypeName(row.vulnerability_category) }}
                </el-tag>
              </template>
            </el-table-column>
            
            <el-table-column prop="cvss_base_score" label="CVSS评分" width="180" align="center">
              <template #default="{ row }">
                <div class="cvss-score">
                  <el-rate
                    v-model="row.cvss_base_score"
                    :max="10"
                    disabled
                    show-score
                    :colors="['#67C23A', '#E6A23C', '#F56C6C']"
                  />
                  <span class="severity-tag" :class="getSeverityClass(row.cvss_base_score)">
                    {{ getSeverityLabel(row.cvss_base_score) }}
                  </span>
                </div>
              </template>
            </el-table-column>
            
            <el-table-column prop="date_published" label="发布日期" width="150" align="center">
              <template #default="{ row }">
                <span class="date-text">{{ formatDate(row.date_published) }}</span>
              </template>
            </el-table-column>

            <el-table-column label="操作" width="120" align="center">
              <template #default="{ row }">
                <el-button type="primary" link @click.stop="showDetails(row)">
                  查看详情
                </el-button>
              </template>
            </el-table-column>
          </el-table>

          <!-- 分页 -->
          <div class="pagination">
            <el-pagination
              v-model:current-page="currentPage"
              v-model:page-size="pageSize"
              :page-sizes="[10, 20, 50, 100]"
              :total="total"
              layout="total, sizes, prev, pager, next, jumper"
              background
              @size-change="handleSizeChange"
              @current-change="handleCurrentChange"
            />
          </div>
        </el-card>

        <!-- 详情抽屉 -->
        <el-drawer
          v-model="drawerVisible"
          :title="`漏洞详情 - ${currentVulnerability?.cve_id || ''}`"
          size="50%"
          direction="rtl"
        >
          <div v-if="currentVulnerability" class="vulnerability-details">
            <el-descriptions :column="1" border>
              <el-descriptions-item label="CVE ID">
                <el-tag size="large">{{ currentVulnerability.cve_id }}</el-tag>
              </el-descriptions-item>
              
              <el-descriptions-item label="漏洞类型">
                <el-tag 
                  :type="getTypeTagType(currentVulnerability.vulnerability_category)"
                  size="large"
                >
                  {{ getVulnerabilityTypeName(currentVulnerability.vulnerability_category) }}
                </el-tag>
              </el-descriptions-item>
              
              <el-descriptions-item label="CVSS评分">
                <div class="cvss-score-detail">
                  <el-rate
                    v-model="currentVulnerability.cvss_base_score"
                    :max="10"
                    disabled
                    show-score
                    :colors="['#67C23A', '#E6A23C', '#F56C6C']"
                  />
                  <span class="severity-tag" :class="getSeverityClass(currentVulnerability.cvss_base_score)">
                    {{ getSeverityLabel(currentVulnerability.cvss_base_score) }}
                  </span>
                </div>
              </el-descriptions-item>
              
              <el-descriptions-item label="发布日期">
                {{ formatDate(currentVulnerability.date_published) }}
              </el-descriptions-item>
              
              <el-descriptions-item label="描述">
                {{ currentVulnerability.description }}
              </el-descriptions-item>
              
              <el-descriptions-item label="影响产品">
                {{ currentVulnerability.affected_products || '暂无数据' }}
              </el-descriptions-item>
              
              <el-descriptions-item label="参考链接">
                <template v-if="currentVulnerability.references?.length">
                  <div v-for="(link, index) in currentVulnerability.references" :key="index" class="reference-link">
                    <el-link :href="link" target="_blank" type="primary">{{ link }}</el-link>
                  </div>
                </template>
                <template v-else>暂无参考链接</template>
              </el-descriptions-item>
            </el-descriptions>
          </div>
        </el-drawer>
      </el-main>
    </el-container>
  </div>
</template>

<script>
import { ref, onMounted } from 'vue'
import { useRoute } from 'vue-router'
import { Search } from '@element-plus/icons-vue'
import axios from 'axios'
import { ElMessage } from 'element-plus'

export default {
  name: 'CVEList',
  components: { Search },
  setup() {
    const route = useRoute()
    const loading = ref(false)
    const tableData = ref([])
    const total = ref(0)
    const currentPage = ref(1)
    const pageSize = ref(20)
    const searchQuery = ref('')
    const selectedType = ref('')
    const selectedSeverity = ref('')
    const drawerVisible = ref(false)
    const currentVulnerability = ref(null)
    const vulnerabilityTypes = ref([])

    // 漏洞类型中英文映射
    const typeNameMap = {
      'SQL Injection': 'SQL注入',
      'Cross-Site Scripting': '跨站脚本（XSS）',
      'Remote Code Execution': '远程代码执行（RCE）',
      'Buffer Overflow': '缓冲区溢出',
      'Path Traversal': '路径遍历',
      'Denial of Service': '拒绝服务（DoS）',
      'Cross-Site Request Forgery': '跨站请求伪造（CSRF）',
      'Server-Side Request Forgery': '服务器端请求伪造（SSRF）',
      'XML External Entity': 'XML外部实体注入（XXE）',
      'File Upload': '文件上传漏洞'
    }

    // 漏洞类型标签样式映射
    const typeMap = {
      1: 'danger',    // SQL注入
      2: 'warning',   // XSS
      3: 'danger',    // RCE
      4: 'warning',   // Buffer Overflow
      5: 'info',      // Path Traversal
      6: 'info',      // DoS
      7: 'warning',   // CSRF
      8: 'warning',   // SSRF
      9: 'danger',    // XXE
      10: 'info'      // File Upload
    }

    // 严重程度选项
    const severityOptions = [
      { value: 'critical', label: '严重' },
      { value: 'high', label: '高危' },
      { value: 'medium', label: '中危' },
      { value: 'low', label: '低危' },
      { value: 'unknown', label: '未知' }
    ]

    // 获取漏洞类型列表
    const fetchVulnerabilityTypes = async () => {
      try {
        const { data } = await axios.get('http://localhost:5000/api/vulnerability-types')
        vulnerabilityTypes.value = data
      } catch (error) {
        ElMessage.error('获取漏洞类型列表失败')
      }
    }

    // 获取漏洞类型名称
    const getVulnerabilityTypeName = (categoryId) => {
      const type = vulnerabilityTypes.value.find(t => t.category_id === categoryId)
      return type ? `${type.type_name} (${typeNameMap[type.type_name] || type.type_name})` : '未分类'
    }

    // 获取漏洞类型标签样式
    const getTypeTagType = (categoryId) => typeMap[categoryId] || 'info'

    // 获取严重程度标签样式
    const getSeverityTagType = (severity) => {
      const typeMap = {
        'critical': 'danger',
        'high': 'warning',
        'medium': 'success',
        'low': '',
        'unknown': 'info'
      }
      return typeMap[severity]
    }

    // 获取严重程度标签文本
    const getSeverityLabel = (score) => {
      if (score >= 9.0) return '严重'
      if (score >= 7.0) return '高危'
      if (score >= 4.0) return '中危'
      if (score >= 0.1) return '低危'
      return '未知'
    }

    // 获取严重程度样式类名
    const getSeverityClass = (score) => {
      if (score >= 9.0) return 'critical'
      if (score >= 7.0) return 'high'
      if (score >= 4.0) return 'medium'
      if (score >= 0.1) return 'low'
      return 'unknown'
    }

    // 获取漏洞数据
    const fetchData = async () => {
      loading.value = true
      try {
        const { data } = await axios.get('http://localhost:5000/api/vulnerabilities', {
          params: {
            page: currentPage.value,
            per_page: pageSize.value,
            search: searchQuery.value,
            type: selectedType.value,
            severity: selectedSeverity.value
          }
        })
        tableData.value = data.items
        total.value = data.total
      } catch (error) {
        ElMessage.error('获取漏洞数据失败')
      } finally {
        loading.value = false
      }
    }

    // 搜索处理
    const handleSearch = () => {
      currentPage.value = 1
      fetchData()
    }

    // 页码大小变化处理
    const handleSizeChange = (val) => {
      pageSize.value = val
      currentPage.value = 1
      fetchData()
    }

    // 页码变化处理
    const handleCurrentChange = (val) => {
      currentPage.value = val
      fetchData()
    }

    // 显示详情
    const showDetails = async (row) => {
      try {
        const { data } = await axios.get(`http://localhost:5000/api/vulnerability/${row.cve_id}`)
        currentVulnerability.value = data
        drawerVisible.value = true
      } catch (error) {
        ElMessage.error('获取漏洞详情失败')
      }
    }

    // 格式化日期
    const formatDate = (dateString) => dateString ? new Date(dateString).toLocaleDateString() : ''

    // 组件挂载时执行
    onMounted(async () => {
      await fetchVulnerabilityTypes()
      if (route.query.type) {
        selectedType.value = parseInt(route.query.type)
      }
      fetchData()
    })

    return {
      loading,
      tableData,
      total,
      currentPage,
      pageSize,
      searchQuery,
      selectedType,
      selectedSeverity,
      severityOptions,
      typeNameMap,
      drawerVisible,
      currentVulnerability,
      vulnerabilityTypes,
      getVulnerabilityTypeName,
      getTypeTagType,
      getSeverityTagType,
      getSeverityLabel,
      getSeverityClass,
      handleSearch,
      handleSizeChange,
      handleCurrentChange,
      showDetails,
      formatDate
    }
  }
}
</script>

<style scoped>
.cve-list {
  padding: 20px;
  background-color: #f5f7fa;
  min-height: calc(100vh - 40px);
}

.page-header {
  margin-bottom: 20px;
}

.title-section {
  display: flex;
  align-items: center;
  gap: 12px;
  margin-bottom: 20px;
}

.title-section h2 {
  margin: 0;
  font-size: 24px;
  color: #303133;
}

.toolbar {
  display: flex;
  gap: 20px;
  margin-bottom: 20px;
}

.search-input {
  width: 300px;
}

.type-select {
  width: 250px;
}

.severity-select {
  width: 150px;
}

.table-card {
  margin-bottom: 20px;
}

.type-option {
  display: flex;
  align-items: center;
  gap: 8px;
}

.severity-option {
  display: flex;
  align-items: center;
  width: 100%;
}

.type-name {
  font-size: 14px;
  color: #303133;
}

.type-chinese {
  color: #909399;
  font-size: 13px;
}

.cvss-score {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 4px;
}

.severity-tag {
  padding: 2px 6px;
  border-radius: 4px;
  font-size: 12px;
}

.severity-tag.critical {
  background-color: #fef0f0; 
  color: #f56c6c;
  border: 1px solid #fde2e2;
}

.severity-tag.high {
  background-color: #fdf6ec;
  color: #e6a23c;
  border: 1px solid #faecd8;
}

.severity-tag.medium {
  background-color: #f0f9eb;
  color: #67c23a;
  border: 1px solid #e1f3d8;
}

.severity-tag.low {
  background-color: #ecf5ff;
  color: #409eff;
  border: 1px solid #d9ecff;
}

.severity-tag.unknown {
  background-color: #f4f4f5;
  color: #909399;
  border: 1px solid #e9e9eb;
}

.date-text {
  color: #606266;
}

.pagination {
  margin-top: 20px;
  display: flex;
  justify-content: center;
}

.vulnerability-details {
  padding: 20px;
}

.reference-link {
  margin-bottom: 8px;
}

.cvss-score-detail {
  display: flex;
  align-items: center;
  gap: 12px;
}

/* 评分组件样式 */
.el-rate {
  height: 20px;
  line-height: 20px;
  display: inline-flex;
  align-items: center;
}

.el-rate__icon {
  font-size: 14px !important;
  margin-right: 2px;
}

.el-rate__text {
  font-size: 12px;
  margin-left: 4px;
  line-height: 1;
}

/* 详情抽屉中的样式调整 */
.vulnerability-details {
  .el-descriptions {
    padding: 0 20px;
  }

  .el-rate__icon {
    font-size: 16px !important;
  }

  .severity-tag {
    font-size: 13px;
    padding: 3px 8px;
  }

  .reference-link {
    word-break: break-all;
  }
}

/* 响应式调整 */
@media screen and (max-width: 768px) {
  .toolbar {
    flex-direction: column;
    gap: 12px;
  }

  .search-input,
  .type-select,
  .severity-select {
    width: 100%;
  }

  .cvss-score {
    flex-direction: row;
    gap: 8px;
  }
}

/* 表格hover效果 */
.el-table__row {
  cursor: pointer;
  transition: background-color 0.3s;

  &:hover {
    background-color: #f5f7fa !important;
  }
}

/* 工具栏组件间距 */
.toolbar > * {
  flex-shrink: 0;
}

/* 详情抽屉中的链接样式 */
.reference-link .el-link {
  display: block;
  word-break: break-all;
  margin-bottom: 4px;
}

/* 表格内容垂直居中 */
.el-table {
  --el-table-row-height: 50px;
  
  .el-table__cell {
    vertical-align: middle;
  }
}
</style>