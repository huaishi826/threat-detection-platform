<template>
  <div class="app-container dark">
    <Dashboard />
  </div>
</template>

<script setup>
import Dashboard from './views/Dashboard.vue'
</script>

<style>
html, body, #app {
  margin: 0;
  padding: 0;
  height: 100%;
  background: #0a0e17;
  color: #e0e6ed;
  font-family: 'Segoe UI', 'PingFang SC', 'Microsoft YaHei', sans-serif;
}
.app-container {
  height: 100%;
}
</style>
