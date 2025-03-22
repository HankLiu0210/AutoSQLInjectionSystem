<template>
  <div class="home" v-loading="loading" element-loading-text="加载中...">
    <el-container>
      <el-main>
        <h1>CVE漏洞数据库管理系统</h1>

        <!-- 功能卡片区域 -->
        <el-row :gutter="20" class="feature-row">
          <!-- 漏洞总数卡片 -->
          <el-col :span="8">
            <el-card 
              class="feature-card clickable-card"
              @click="navigateToCVEList()">
              <template #header>
                <div class="card-header">
                  <span>漏洞总数</span>
                </div>
              </template>
              <div class="card-content">
                <div class="total-number">
                {{ totalVulnerabilities.toLocaleString() }}
                </div>
              </div>
            </el-card>
          </el-col>
          
          <el-col :span="8">
            <el-card 
              class="feature-card clickable-card"
              @click="navigateToAnalysis()">
              <template #header>
                <div class="card-header">
                  <span>数据分析</span>
                </div>
              </template>
              <div class="card-content">
                <el-icon :size="40" color="#409EFF"><TrendCharts /></el-icon>
                <span class="feature-text">查看详细分析</span>
              </div>
            </el-card>
          </el-col>
          
          <el-col :span="8">
            <el-card 
              class="feature-card clickable-card"
              @click="navigateToCVEList()">
              <template #header>
                <div class="card-header">
                  <span>漏洞库</span>
                </div>
              </template>
              <div class="card-content">
                <el-icon :size="40" color="#67C23A"><List /></el-icon>
                <span class="feature-text">浏览所有漏洞</span>
              </div>
            </el-card>
          </el-col>
        </el-row>

        <!-- 漏洞类型分布卡片组 -->
        <h2 class="section-title">漏洞类型分布</h2>
        <div class="vulnerability-types-container">
          <el-row :gutter="20">
            <el-col 
              :span="6" 
              v-for="type in vulnerabilityTypes" 
              :key="type.category_id">
              <el-card 
                class="type-card clickable-card"
                @click="navigateToCVEList(type.category_id)">
                <template #header>
                  <div class="card-header">
                    <div class="type-name">
                      <div class="en">{{ type.type_name }}</div>
                      <div class="zh">{{ typeNameMap[type.type_name] }}</div>
                    </div>
                  </div>
                </template>
                <div class="card-content">
                  {{ type.count.toLocaleString() }}
                  <span class="percentage">{{ type.percentage }}%</span>
                </div>
              </el-card>
            </el-col>
          </el-row>
        </div>
      </el-main>
    </el-container>
  </div>
</template>

<script>
import { ref, onMounted } from 'vue'
import { useRouter } from 'vue-router'
import axios from 'axios'
import { ElMessage } from 'element-plus'
import { TrendCharts, List } from '@element-plus/icons-vue'

export default {
  name: 'HomeView',
  components: {
    TrendCharts,
    List
  },
  setup() {
    const router = useRouter()
    const loading = ref(true)
    const totalVulnerabilities = ref(0)
    const vulnerabilityTypes = ref([])
    const error = ref(null)

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

    // 获取仪表盘数据
    const fetchDashboardData = async () => {
      loading.value = true
      error.value = null
      try {
        console.log("开始请求仪表盘数据...")
        const response = await axios.get('http://localhost:5000/api/dashboard/stats')
        console.log("API响应数据:", response.data)

        if (!response.data) {
          throw new Error('API返回数据为空')
        }

        const { 
          total_vulnerabilities, 
          vulnerability_types
        } = response.data

        // 更新总数和类型数据
        totalVulnerabilities.value = total_vulnerabilities || 0
        vulnerabilityTypes.value = vulnerability_types || []

      } catch (err) {
        console.error('仪表盘数据获取错误:', err)
        error.value = err.message
        ElMessage.error(`获取数据失败: ${err.message}`)
      } finally {
        loading.value = false
      }
    }

    // 导航到漏洞列表
    const navigateToCVEList = (categoryId = null) => {
      router.push({
        path: '/cve-list',
        query: categoryId ? { type: categoryId } : {}
      })
    }

    // 导航到数据分析页面
    const navigateToAnalysis = () => {
      router.push('/analysis')
    }

    onMounted(() => {
      fetchDashboardData()
    })

    return {
      loading,
      error,
      totalVulnerabilities,
      vulnerabilityTypes,
      typeNameMap,
      navigateToCVEList,
      navigateToAnalysis
    }
  }
}
</script>

<style scoped>
.home {
  padding: 20px;
  min-height: 100vh;
  background-color: #f5f7fa;
}

/* 功能卡片样式 */
.feature-row {
  margin-bottom: 30px;
}

.feature-card {
  height: 200px;
  transition: all 0.3s;
  display: flex;
  flex-direction: column;
}

.feature-card .card-content {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  gap: 16px;
}

.feature-text {
  font-size: 16px;
  color: #606266;
  text-align: center;
}

/* 卡片样式 */
.card-header {
  font-weight: bold;
  color: #303133;
  padding: 10px 0;
  font-size: 24px;
}

.card-content {
  /* font-size: 32px;
  text-align: center;
  padding: 20px 0;
  display: flex;
  justify-content: center;
  align-items: center;
  min-height: 100px; */
  font-size: 32px;
  text-align: center;
  padding: 30px 0 0 0;
  display: flex;
  flex-direction: column; /* 改为纵向排列 */
  justify-content: center;
  align-items: center;
  height: calc(100% - 60px); /* 减去header的高度 */
}

.total-number {
  /* font-size: 40px;
  font-weight: bold;
  color: #409EFF; */
  font-size: 40px;
  font-weight: bold;
  color: #409EFF;
  display: flex;
  justify-content: center;
  align-items: center;
  width: 100%;
  height: 100%;
  margin: 0; /* 移除外边距 */
}

.feature-content {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  gap: 10px;
  height: 100%;
}


/* 漏洞类型卡片样式 */
.section-title {
  margin: 30px 0 20px;
  color: #303133;
  font-size: 24px;
}

.vulnerability-types-container {
  margin-top: 20px;
}

.type-card {
  margin-bottom: 20px;
  height: 100%;
  min-height: 160px;
}

.type-name {
  text-align: center;
}

.type-name .en {
  font-size: 16px;
  margin-bottom: 4px;
}

.type-name .zh {
  font-size: 14px;
  color: #606266;
}

.type-card .card-content {
  font-size: 24px;
  padding: 20px 0;
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 10px;
}

.percentage {
  font-size: 16px;
  color: #909399;
  margin-left: 8px;
}

/* 交互样式 */
.clickable-card {
  cursor: pointer;
  transition: all 0.3s;
}

.clickable-card:hover {
  transform: translateY(-5px);
  box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
}

/* 响应式布局 */
@media (max-width: 1200px) {
  .el-col {
    width: 33.33%;
  }
}

@media (max-width: 768px) {
  .el-col {
    width: 50%;
  }
}

@media (max-width: 576px) {
  .el-col {
    width: 100%;
  }
}
</style>