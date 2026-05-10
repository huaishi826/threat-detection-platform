<template>
  <div class="history-page">
    <header class="nav-bar">
      <div class="nav-brand">
        <router-link to="/" class="back-link">← 返回仪表盘</router-link>
        <span class="divider">|</span>
        <span class="page-title">📋 历史扫描记录</span>
      </div>
      <div class="nav-right">
        <router-link to="/settings" class="nav-link">⚙️ 设置</router-link>
        <span class="clock">{{ currentTime }}</span>
      </div>
    </header>

    <div class="table-card">
      <el-table
        :data="scans"
        stripe
        style="width: 100%"
        :header-cell-style="{ background: '#1e293b', color: '#94a3b8', borderColor: '#334155' }"
        :cell-style="{ background: '#0f172a', color: '#e2e8f0', borderColor: '#334155' }"
        v-loading="loading"
      >
        <el-table-column prop="id" label="ID" width="70" />
        <el-table-column label="扫描时间" min-width="180">
          <template #default="{ row }">
            {{ formatTime(row.timestamp) }}
          </template>
        </el-table-column>
        <el-table-column prop="total_packets" label="总包数" width="100" />
        <el-table-column label="告警总数" width="100">
          <template #default="{ row }">
            <el-tag v-if="row.alert_count > 0" type="danger" size="small">{{ row.alert_count }}</el-tag>
            <span v-else style="color: #64748b">0</span>
          </template>
        </el-table-column>
        <el-table-column prop="rule_alert_count" label="规则告警" width="100" />
        <el-table-column prop="ml_alert_count" label="ML告警" width="100" />
        <el-table-column label="操作" width="140">
          <template #default="{ row }">
            <el-button size="small" type="primary" plain @click="goDetail(row.id)">
              查看详情
            </el-button>
          </template>
        </el-table-column>
      </el-table>

      <div class="pagination-wrapper">
        <el-pagination
          v-model:current-page="currentPage"
          :page-size="perPage"
          :total="total"
          layout="prev, pager, next, total"
          background
          @current-change="fetchScans"
        />
      </div>
    </div>

    <div v-if="!loading && scans.length === 0" class="empty-state">
      <div class="empty-icon">📂</div>
      <div class="empty-text">暂无历史扫描记录</div>
      <router-link to="/" class="empty-link">前往仪表盘开始第一次扫描 →</router-link>
    </div>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import { useRouter } from 'vue-router'
import axios from 'axios'

const router = useRouter()
const scans = ref([])
const loading = ref(true)
const currentPage = ref(1)
const perPage = ref(20)
const total = ref(0)
const currentTime = ref('')

function formatTime(iso) {
  if (!iso) return '-'
  if (typeof iso === 'string' && !iso.includes('T') && !iso.includes('-')) return iso
  let d = new Date(iso)
  if (isNaN(d.getTime()) && typeof iso === 'string' && !iso.includes('+') && !iso.endsWith('Z')) {
    d = new Date(iso + 'Z')
  }
  if (isNaN(d.getTime())) return iso
  return d.toLocaleString('zh-CN', {
    year: 'numeric', month: '2-digit', day: '2-digit',
    hour: '2-digit', minute: '2-digit', second: '2-digit',
  })
}

function goDetail(id) {
  router.push(`/history/${id}`)
}

async function fetchScans() {
  loading.value = true
  try {
    const { data } = await axios.get('/api/scans', {
      params: { page: currentPage.value, per_page: perPage.value },
    })
    scans.value = data.scans
    total.value = data.total
  } catch (e) {
    console.error(e)
  } finally {
    loading.value = false
  }
}

function updateClock() {
  currentTime.value = new Date().toLocaleTimeString()
}

onMounted(() => {
  fetchScans()
  updateClock()
  setInterval(updateClock, 1000)
})
</script>

<style scoped>
.history-page {
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

.nav-link {
  color: #3b82f6;
  text-decoration: none;
  font-size: 14px;
  padding: 6px 14px;
  border: 1px solid #334155;
  border-radius: 8px;
  transition: all 0.2s;
}
.nav-link:hover {
  border-color: #3b82f6;
  background: rgba(59, 130, 246, 0.1);
}

.clock {
  font-family: 'JetBrains Mono', monospace;
  color: #64748b;
  font-size: 13px;
}

.table-card {
  background: #0f172a;
  border-radius: 10px;
  overflow: hidden;
}

.pagination-wrapper {
  display: flex;
  justify-content: flex-end;
  margin-top: 16px;
  padding: 10px 0;
}

.empty-state {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  padding: 80px 0 40px;
}
.empty-icon {
  font-size: 64px;
  margin-bottom: 16px;
  opacity: 0.4;
}
.empty-text {
  font-size: 15px;
  color: #475569;
  margin-bottom: 12px;
}
.empty-link {
  color: #3b82f6;
  text-decoration: none;
  font-size: 14px;
}
</style>
