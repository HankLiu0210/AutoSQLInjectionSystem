<template>
    <div class="cve-list">
      <h1>CVE漏洞知识库</h1>
      <el-card class="filter-card">
        <el-form :inline="true" :model="filterForm">
          <el-form-item label="漏洞类型">
            <el-select v-model="filterForm.type" placeholder="全部类型" clearable>
              <el-option
                v-for="type in vulnerabilityTypes"
                :key="type.category_id"
                :label="type.type_name"
                :value="type.category_id"
              />
            </el-select>
          </el-form-item>
          <el-form-item label="关键词">
            <el-input v-model="filterForm.keyword" placeholder="搜索CVE ID或描述" />
          </el-form-item>
          <el-form-item>
            <el-button type="primary" @click="handleSearch">搜索</el-button>
            <el-button @click="handleReset">重置</el-button>
          </el-form-item>
        </el-form>
      </el-card>
  
      <el-table
        v-loading="loading"
        :data="cveList"
        style="width: 100%; margin-top: 20px;">
        <el-table-column prop="cve_id" label="CVE ID" width="180" />
        <el-table-column prop="description" label="描述" />
        <el-table-column prop="cvss_base_score" label="CVSS评分" width="100" />
        <el-table-column prop="date_published" label="发布日期" width="180" />
        <el-table-column fixed="right" label="操作" width="100">
          <template #default="scope">
            <el-button @click="viewDetail(scope.row)" type="text" size="small">
              查看详情
            </el-button>
          </template>
        </el-table-column>
      </el-table>
  
      <div class="pagination">
        <el-pagination
          @current-change="handlePageChange"
          :current-page="currentPage"
          :page-size="pageSize"
          :total="total"
          layout="total, prev, pager, next"
        />
      </div>
    </div>
  </template>
  
  <script>
  export default {
    name: 'CVEListView',
    data() {
      return {
        loading: false,
        filterForm: {
          type: null,
          keyword: ''
        },
        vulnerabilityTypes: [
          { category_id: 1, type_name: 'SQL注入' },
          { category_id: 2, type_name: 'XSS跨站脚本' },
          { category_id: 3, type_name: '远程代码执行' },
          // ... 其他漏洞类型
        ],
        cveList: [],
        currentPage: 1,
        pageSize: 20,
        total: 0
      }
    },
    created() {
      // 从 URL 查询参数获取类型
      const typeFromQuery = this.$route.query.type
      if (typeFromQuery) {
        this.filterForm.type = Number(typeFromQuery)
      }
      this.fetchCVEList()
    },
    methods: {
      async fetchCVEList() {
        this.loading = true
        // TODO: 实现API调用
        // 临时使用模拟数据
        setTimeout(() => {
          this.cveList = [
            {
              cve_id: 'CVE-2023-1234',
              description: '示例漏洞描述',
              cvss_base_score: 7.5,
              date_published: '2023-01-01'
            }
            // ... 更多数据
          ]
          this.total = 100
          this.loading = false
        }, 500)
      },
      handleSearch() {
        this.currentPage = 1
        this.fetchCVEList()
      },
      handleReset() {
        this.filterForm = {
          type: null,
          keyword: ''
        }
        this.handleSearch()
      },
      handlePageChange(page) {
        this.currentPage = page
        this.fetchCVEList()
      },
      viewDetail(row) {
        this.$router.push(`/cve/${row.cve_id}`)
      }
    }
  }
  </script>
  
  <style scoped>
  .cve-list {
    padding: 20px;
  }
  
  .filter-card {
    margin-bottom: 20px;
  }
  
  .pagination {
    margin-top: 20px;
    text-align: right;
  }
  </style>