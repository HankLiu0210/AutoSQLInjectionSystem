<template>
  <div class="visualization-container">
    <!-- 统计卡片 -->
    <el-row :gutter="20" class="stat-cards">
      <el-col :span="6" v-for="(stat, index) in statisticsData" :key="index">
        <el-card class="stat-card" shadow="hover">
          <div class="stat-content">
            <div class="stat-value">{{ stat.value }}</div>
            <div class="stat-label">{{ stat.label }}</div>
          </div>
        </el-card>
      </el-col>
    </el-row>

    <!-- 图表区域 -->
    <el-row :gutter="20" class="chart-row">
      <el-col :span="16">
        <el-card class="chart-card">
          <template #header>
            <div class="chart-header">
              <span>漏洞趋势分析</span>
            </div>
          </template>
          <v-chart class="chart" :option="trendOption" autoresize />
        </el-card>
      </el-col>
      <el-col :span="8">
        <el-card class="chart-card">
          <template #header>
            <div class="chart-header">
              <span>漏洞类型分布</span>
            </div>
          </template>
          <v-chart class="chart" :option="pieOption" autoresize />
        </el-card>
      </el-col>
    </el-row>
  </div>
          </template>
<script>
import { ref, onMounted } from 'vue'
import VChart from 'vue-echarts'
import { use } from 'echarts/core'
import { CanvasRenderer } from 'echarts/renderers'
import { PieChart, LineChart } from 'echarts/charts'
import {
  TitleComponent,
  TooltipComponent,
  LegendComponent,
  GridComponent
} from 'echarts/components'

// 注册 ECharts 必需的组件
use([
  CanvasRenderer,
  PieChart,
  LineChart,
  TitleComponent,
  TooltipComponent,
  LegendComponent,
  GridComponent
])

export default {
  name: 'DataVisualization',
  components: {
    VChart
  },
  setup() {
    const statisticsData = ref([
      { label: '总漏洞数', value: '0' },
      { label: '已分类漏洞', value: '0' },
      { label: '高危漏洞', value: '0' },
      { label: '本月新增', value: '0' }
    ])

    // 趋势图配置
    const trendOption = ref({
      tooltip: {
        trigger: 'axis'
      },
      legend: {
        data: ['总漏洞数', '高危漏洞']
      },
      grid: {
        left: '3%',
        right: '4%',
        bottom: '3%',
        containLabel: true
      },
      xAxis: {
        type: 'category',
        boundaryGap: false,
        data: ['1月', '2月', '3月', '4月', '5月', '6月']
      },
      yAxis: {
        type: 'value'
      },
      series: [
        {
          name: '总漏洞数',
          type: 'line',
          data: [100, 120, 140, 160, 180, 200],
          smooth: true
        },
        {
          name: '高危漏洞',
          type: 'line',
          data: [30, 40, 50, 60, 70, 80],
          smooth: true
        }
      ]
    })
    // 饼图配置
    const pieOption = ref({
      tooltip: {
        trigger: 'item',
        formatter: '{a} <br/>{b}: {c} ({d}%)'
      },
      legend: {
        orient: 'vertical',
        left: 10,
        data: ['SQL注入', 'XSS', 'RCE', '文件上传', '其他']
      },
      series: [
        {
          name: '漏洞类型',
          type: 'pie',
          radius: ['50%', '70%'],
          avoidLabelOverlap: false,
          itemStyle: {
            borderRadius: 10,
            borderColor: '#fff',
            borderWidth: 2
          },
          label: {
            show: false,
            position: 'center'
          },
          emphasis: {
        label: {
              show: true,
              fontSize: 40,
              fontWeight: 'bold'
        }
          },
          labelLine: {
            show: false
          },
          data: [
            { value: 335, name: 'SQL注入' },
            { value: 310, name: 'XSS' },
            { value: 234, name: 'RCE' },
            { value: 135, name: '文件上传' },
            { value: 148, name: '其他' }
          ]
    }
      ]
    })

    return {
      statisticsData,
      trendOption,
      pieOption
    }
  }
}
</script>

<style scoped>
.visualization-container {
  padding: 20px;
}

.stat-cards {
  margin-bottom: 20px;
}

.stat-card {
  height: 120px;
  transition: all 0.3s;
}

.stat-card:hover {
  transform: translateY(-5px);
  box-shadow: 0 2px 12px 0 rgba(0,0,0,.1);
}

.stat-content {
  text-align: center;
  padding: 20px;
}

.stat-value {
  font-size: 24px;
  font-weight: bold;
  color: #303133;
  margin-bottom: 8px;
}

.stat-label {
  font-size: 14px;
  color: #909399;
}

.chart-row {
  margin-bottom: 20px;
}

.chart-card {
  margin-bottom: 20px;
}

.chart-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 0 20px;
}

.chart {
  height: 400px;
}
</style>