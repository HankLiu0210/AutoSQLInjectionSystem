<template>
  <div class="nav-bar">
    <el-menu
      :router="true"
      mode="horizontal"
      class="nav-menu">
      <el-menu-item index="/">首页</el-menu-item>
      <el-menu-item index="/cve-list">CVE漏洞知识库</el-menu-item>
      <el-menu-item index="/analysis">漏洞数据分析</el-menu-item>
    </el-menu>
  </div>
</template>

<script>
export default {
  name: 'NavBar'
}
</script>

<style scoped>
.nav-bar {
  border-bottom: 1px solid #eee;
}

.nav-menu {
  padding-left: 20px;
}
</style>