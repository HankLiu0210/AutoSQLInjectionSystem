<template>
  <div class="data-analysis" v-loading="loading" element-loading-text="加载中...">
    <el-container>
      <el-main>
        <h1>漏洞数据分析</h1>

        <!-- 趋势分析图表 -->
        <el-row :gutter="20" class="visualization-row">
          <el-col :span="24">
            <el-card class="visualization-card">
              <template #header>
                <div class="visualization-header">
                  <span>漏洞趋势分析</span>
                  <el-tooltip content="显示1999年~2025年漏洞数量变化趋势" placement="top">
                    <el-icon><InfoFilled /></el-icon>
                  </el-tooltip>
                </div>
              </template>
              <div class="chart-container">
                <div v-if="!loading" class="chart-wrapper">
                  <apexchart
                    ref="trendChart"
                    type="line"
                    :height="chartHeight"
                    :width="trendChartWidth"
                    :options="trendChartOptions"
                    :series="trendChartSeries"
                  />
                </div>
              </div>
            </el-card>
          </el-col>
        </el-row>

        <!-- 分布分析图表 -->
        <el-row :gutter="20" class="visualization-row">
          <el-col :span="12">
            <el-card class="visualization-card">
              <template #header>
                <div class="visualization-header">
                  <span>漏洞类型分布</span>
                  <el-tooltip content="各类型漏洞占比统计" placement="top">
                    <el-icon><InfoFilled /></el-icon>
                  </el-tooltip>
                </div>
              </template>
              <div class="chart-container">
                <div v-if="!loading" class="chart-wrapper">
                  <apexchart
                    ref="typeChart"
                    type="donut"
                    :height="chartHeight"
                    :width="donutChartWidth"
                    :options="typeChartOptions"
                    :series="typeChartSeries"
                  />
                </div>
              </div>
            </el-card>
          </el-col>
          <el-col :span="12">
            <el-card class="visualization-card">
              <template #header>
                <div class="visualization-header">
                  <span>严重程度分布</span>
                  <el-tooltip content="按CVSS评分划分的漏洞严重程度分布" placement="top">
                    <el-icon><InfoFilled /></el-icon>
                  </el-tooltip>
                </div>
              </template>
              <div class="chart-container">
                <div v-if="!loading" class="chart-wrapper">
                  <apexchart
                    ref="severityChart"
                    type="donut"
                    :height="chartHeight"
                    :width="donutChartWidth"
                    :options="severityChartOptions"
                    :series="severityChartSeries"
                  />
                </div>
              </div>
            </el-card>
          </el-col>
        </el-row>
      </el-main>
    </el-container>
  </div>
</template>

<script>
import { defineComponent, ref, onMounted, nextTick } from 'vue'
import axios from 'axios'
import { ElMessage } from 'element-plus'
import { InfoFilled } from '@element-plus/icons-vue'
import VueApexCharts from 'vue3-apexcharts'

export default defineComponent({
  name: 'DataAnalysis',
  components: {
    apexchart: VueApexCharts,
    InfoFilled
  },
  setup() {
    const loading = ref(true)
    const error = ref(null)
    const chartHeight = 400
    const trendChartWidth = '400%'  // 趋势图宽度
    const donutChartWidth = '200%'  // 环形图宽度


    // 图表引用
    const trendChart = ref(null)
    const typeChart = ref(null)
    const severityChart = ref(null)

    // 趋势图数据
    const trendChartSeries = ref([
      {
        name: '总漏洞数',
        data: []
      },
      {
        name: 'SQL注入',
        data: []
      },
      {
        name: '跨站脚本（XSS）',
        data: []
      },
      {
        name: '远程代码执行（RCE）',
        data: []
      },
      {
        name: '缓冲区溢出',
        data: []
      },
      {
        name: '路径遍历',
        data: []
      },
      {
        name: '拒绝服务（DoS）',
        data: []
      },
      {
        name: '跨站请求伪造（CSRF）',
        data: []
      },
      {
        name: '服务器端请求伪造（SSRF）',
        data: []
      },
      {
        name: 'XML外部实体注入（XXE）',
        data: []
      },
      {
        name: '文件上传漏洞',
        data: []
      }
    ])

    // 漏洞类型数据
    const typeChartSeries = ref([])

    // 严重程度数据
    const severityChartSeries = ref([])

    // 趋势图配置
    const trendChartOptions = ref({
      chart: {
        type: 'line',
        zoom: { 
          enabled: true,
          type: 'x',
          autoScaleYaxis: true
        },
        toolbar: { 
          show: false,
          tools: {
            download: true,
            selection: true,
            zoom: true,
            zoomin: true,
            zoomout: true,
            pan: true,
            reset: true
          }
        }
      },
      stroke: {
        curve: 'smooth',
        width: 2
      },
      colors: [
        '#409EFF', // 总数 - 蓝色
        '#F56C6C', // SQL注入 - 红色
        '#E6A23C', // XSS - 橙色
        '#F56C6C', // RCE - 红色
        '#E6A23C', // Buffer Overflow - 橙色
        '#67C23A', // Path Traversal - 绿色
        '#67C23A', // DoS - 绿色
        '#E6A23C', // CSRF - 橙色
        '#E6A23C', // SSRF - 橙色
        '#F56C6C', // XXE - 红色
        '#67C23A'  // File Upload - 绿色
      ],
      xaxis: {
        categories: [],
        title: {
          text: '年份'
        },
        labels: {
          rotate: -45,
          rotateAlways: true
        }
      },
      yaxis: {
        title: {
          text: '漏洞数量'
        },
        labels: {
          formatter: function(value) {
            return Math.round(value)
          }
        }
      },
      legend: {
        position: 'right',
        verticalAlign: 'middle',
        fontSize: '12px'
      },
      tooltip: {
        shared: true,
        intersect: false,
        y: {
          formatter: function(value) {
            return Math.round(value) + ' 个'
          }
        }
      }
    })
    // const trendChartOptions = ref({
    //   chart: {
    //     type: 'line',
    //     zoom: { enabled: false },
    //     toolbar: { show: false },
    //     animations: {
    //       enabled: true,
    //       easing: 'easeinout',
    //       speed: 800
    //     }
    //   },
    //   dataLabels: {
    //     enabled: true,
    //     style: { fontSize: '14px' }
    //   },
    //   stroke: {
    //     curve: 'smooth',
    //     width: 3
    //   },
    //   colors: ['#409EFF', '#F56C6C'],
    //   xaxis: {
    //     categories: [],
    //     title: {
    //       text: '年份',
    //       style: {
    //         fontSize: '14px',
    //         fontWeight: 600
    //       }
    //     },
    //     labels: {
    //       style: { fontSize: '13px' }
    //     }
    //   },
    //   yaxis: {
    //     title: {
    //       text: '漏洞数量',
    //       style: {
    //         fontSize: '14px',
    //         fontWeight: 600
    //       }
    //     },
    //     labels: {
    //       style: { fontSize: '13px' }
    //     }
    //   },
    //   legend: {
    //     position: 'top',
    //     horizontalAlign: 'center',
    //     fontSize: '14px',
    //     markers: {
    //       width: 12,
    //       height: 12
    //     }
    //   },
    //   tooltip: {
    //     theme: 'light',
    //     x: { show: true },
    //     style: { fontSize: '14px' }
    //   }
    // })

    // 类型分布图配置
    const typeChartOptions = ref({
      chart: { type: 'donut' },
      labels: [],
      legend: {
        position: 'right',
        fontSize: '14px',
        formatter: function(seriesName, opts) {
          return `${seriesName}: ${opts.w.globals.series[opts.seriesIndex]}`
        }
      },
      tooltip: {
        y: {
          formatter: function(value) {
            return `${value} 个`
          }
        },
        style: { fontSize: '14px' }
      },
      plotOptions: {
        pie: {
          donut: {
            size: '75%',
            labels: {
              show: true,
              name: { fontSize: '14px' },
              value: {
                fontSize: '16px',
                fontWeight: 600
              },
              total: {
                show: true,
                fontSize: '16px',
                fontWeight: 600
              }
            }
          }
        }
      }
    })

    // 严重程度分布图配置
    const severityChartOptions = ref({
      chart: { type: 'donut' },
      labels: ['严重', '高危', '中危', '低危', '未知'],
      colors: ['#F56C6C', '#E6A23C', '#409EFF', '#67C23A', '#909399'],
      legend: {
        position: 'right',
        fontSize: '14px',
        formatter: function(seriesName, opts) {
          return `${seriesName}: ${opts.w.globals.series[opts.seriesIndex]}`
        }
      },
      tooltip: {
        y: {
          formatter: function(value) {
            return `${value} 个`
          }
        },
        style: { fontSize: '14px' }
      },
      plotOptions: {
        pie: {
          donut: {
            size: '75%',
            labels: {
              show: true,
              name: { fontSize: '14px' },
              value: {
                fontSize: '16px',
                fontWeight: 600
              },
              total: {
                show: true,
                fontSize: '16px',
                fontWeight: 600
              }
            }
          }
        }
      }
    })

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

    // 更新图表数据
    const updateCharts = async (data) => {
      const { vulnerability_types, trend_data, severity_distribution } = data

      if (trend_data?.length > 0) {
        // trendChartOptions.value.xaxis.categories = trend_data.map(item => item.year.toString())
        // trendChartSeries.value[0].data = trend_data.map(item => item.total_count)
        // trendChartSeries.value[1].data = trend_data.map(item => item.high_severity_count)
        trendChartOptions.value.xaxis.categories = trend_data.map(item => item.year.toString())
        trendChartSeries.value[0].data = trend_data.map(item => item.total_count)
        trendChartSeries.value[1].data = trend_data.map(item => item.sql_injection_count)
        trendChartSeries.value[2].data = trend_data.map(item => item.xss_count)
        trendChartSeries.value[3].data = trend_data.map(item => item.rce_count)
        trendChartSeries.value[4].data = trend_data.map(item => item.buffer_overflow_count)
        trendChartSeries.value[5].data = trend_data.map(item => item.path_traversal_count)
        trendChartSeries.value[6].data = trend_data.map(item => item.dos_count)
        trendChartSeries.value[7].data = trend_data.map(item => item.csrf_count)
        trendChartSeries.value[8].data = trend_data.map(item => item.ssrf_count)
        trendChartSeries.value[9].data = trend_data.map(item => item.xxe_count)
        trendChartSeries.value[10].data = trend_data.map(item => item.file_upload_count)
      }

      if (vulnerability_types?.length > 0) {
        typeChartOptions.value.labels = vulnerability_types.map(
          type => typeNameMap[type.type_name] || type.type_name
        )
        typeChartSeries.value = vulnerability_types.map(type => type.count)
      }

      if (severity_distribution?.length > 0) {
        severityChartSeries.value = severity_distribution.map(item => item.count)
      }

      await nextTick()
    }

    // 获取数据
    const fetchAnalysisData = async () => {
      loading.value = true
      try {
        const response = await axios.get('http://localhost:5000/api/dashboard/stats')
        await updateCharts(response.data)
      } catch (err) {
        error.value = err.message
        ElMessage.error(`获取数据失败: ${err.message}`)
      } finally {
        loading.value = false
      }
    }

    onMounted(() => {
      fetchAnalysisData()
    })

    return {
      loading,
      error,
      chartHeight,
      trendChartWidth,    // 添加趋势图宽度
      donutChartWidth,    // 添加环形图宽度
      trendChart,
      typeChart,
      severityChart,
      trendChartOptions,
      trendChartSeries,
      typeChartOptions,
      typeChartSeries,
      severityChartOptions,
      severityChartSeries
    }
  }
})
</script>

<style scoped>
.data-analysis {
  padding: 20px;
  min-height: 100vh;
  background-color: #f5f7fa;
}

.visualization-card {
  height: 600px;
  margin-bottom: 30px;
}

.visualization-header {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 20px;
  border-bottom: 1px solid #EBEEF5;
}

.visualization-header span {
  font-size: 18px;
  font-weight: 600;
}

.chart-container {
  height: calc(100% - 65px);
  padding: 20px;
}

.chart-wrapper {
  width: 100%;
  height: 100%;
  display: flex;
  align-items: center;
  justify-content: center;
}

@media (max-width: 1200px) {
  .el-col {
    width: 100%;
  }
  
  .visualization-card {
    height: 500px;
  }
}

@media (max-width: 768px) {
  .visualization-card {
    height: 400px;
  }
  
  .chart-container {
    padding: 10px;
  }
}
</style>