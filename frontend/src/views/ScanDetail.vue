<template>
  <div class="detail-page">
    <header class="nav-bar">
      <div class="nav-brand">
        <router-link to="/history" class="back-link">← 返回历史列表</router-link>
        <span class="divider">|</span>
        <span class="page-title">🔍 扫描详情 #{{ scanId }}</span>
      </div>
      <div class="nav-right">
        <router-link to="/" class="back-link">仪表盘</router-link>
      </div>
    </header>

    <!-- scan summary cards -->
    <div v-if="scan" class="summary-row">
      <div class="summary-card">
        <div class="card-label">扫描时间</div>
        <div class="card-value" style="font-size:16px">{{ formatTime(scan.timestamp) }}</div>
      </div>
      <div class="summary-card">
        <div class="card-label">总包数</div>
        <div class="card-value">{{ scan.total_packets }}</div>
      </div>
      <div class="summary-card">
        <div class="card-label">告警总数</div>
        <div class="card-value" :class="{ danger: scan.alert_count > 0 }">{{ scan.alert_count }}</div>
      </div>
      <div class="summary-card">
        <div class="card-label">规则 / ML</div>
        <div class="card-value">{{ scan.rule_alert_count }} / {{ scan.ml_alert_count }}</div>
      </div>
    </div>

    <!-- alerts table -->
    <div class="table-card">
      <h3>告警列表（{{ alerts.length }} 条）</h3>
      <el-table
        :data="alerts"
        stripe
        style="width: 100%"
        :header-cell-style="{ background: '#1e293b', color: '#94a3b8', borderColor: '#334155' }"
        :cell-style="{ background: '#0f172a', color: '#e2e8f0', borderColor: '#334155' }"
        max-height="500"
        v-loading="loading"
      >
        <el-table-column prop="timestamp" label="时间" width="180" />
        <el-table-column prop="type" label="类型" width="130" />
        <el-table-column label="等级" width="90">
          <template #default="{ row }">
            <el-tag :type="tagType(row.severity)" size="small">{{ row.severity }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="source_ip" label="源IP" width="150" />
        <el-table-column prop="detail" label="详情" show-overflow-tooltip />
      </el-table>
    </div>

    <div v-if="!loading && alerts.length === 0" class="empty-state">
      <div class="empty-icon">✅</div>
      <div class="empty-text">本次扫描未发现任何告警</div>
    </div>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import { useRoute } from 'vue-router'
import axios from 'axios'

const route = useRoute()
const scanId = route.params.id
const scan = ref(null)
const alerts = ref([])
const loading = ref(true)

function tagType(severity) {
  return { high: 'danger', medium: 'warning', low: 'info' }[severity] || ''
}

function formatTime(iso) {
  if (!iso) return '-'
  return new Date(iso).toLocaleString('zh-CN')
}

async function fetchDetail() {
  loading.value = true
  try {
    const { data } = await axios.get(`/api/scans/${scanId}`)
    scan.value = data.scan
    alerts.value = data.alerts
  } catch (e) {
    console.error(e)
  } finally {
    loading.value = false
  }
}

onMounted(fetchDetail)
</script>

<style scoped>
.detail-page {
  padding: 16px 24px;
  background: #0f172a;
  min-height: 100vh;
  color: #e2e8f0;
}

.nav-bar {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 20px;
  padding-bottom: 14px;
  border-bottom: 1px solid #1e293b;
}

.nav-brand {
  display: flex;
  align-items: center;
  gap: 12px;
}

.back-link {
  color: #3b82f6;
  text-decoration: none;
  font-size: 14px;
}
.back-link:hover { color: #60a5fa; }

.divider { color: #334155; }

.page-title {
  font-size: 18px;
  font-weight: 700;
  background: linear-gradient(135deg, #3b82f6, #8b5cf6);
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
  background-clip: text;
}

.summary-row {
  display: flex;
  gap: 16px;
  margin-bottom: 20px;
}

.summary-card {
  flex: 1;
  background: #1e293b;
  border: 1px solid #334155;
  border-radius: 10px;
  padding: 16px;
  text-align: center;
}
.card-label {
  color: #94a3b8;
  font-size: 13px;
  margin-bottom: 6px;
}
.card-value {
  font-size: 24px;
  font-weight: 700;
  color: #f1f5f9;
}
.card-value.danger { color: #ef4444; }

.table-card {
  background: #1e293b;
  border: 1px solid #334155;
  border-radius: 10px;
  padding: 16px;
}
.table-card h3 {
  margin: 0 0 12px 0;
  font-size: 14px;
  color: #94a3b8;
}

.empty-state {
  display: flex;
  flex-direction: column;
  align-items: center;
  padding: 60px 0;
}
.empty-icon {
  font-size: 48px;
  margin-bottom: 12px;
}
.empty-text {
  color: #475569;
  font-size: 15px;
}
</style>
