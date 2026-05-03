<template>
  <div class="dashboard">
    <!-- ── top nav ─────────────────────────────────── -->
    <header class="nav-bar">
      <h1>🛡️ 威胁检测平台</h1>
      <div class="nav-right">
        <span class="status-dot" :class="{ active: running }" />
        <span>{{ running ? '运行中' : '就绪' }}</span>
        <span class="clock">{{ currentTime }}</span>
      </div>
    </header>

    <!-- ── capture controls ────────────────────────── -->
    <section class="controls">
      <el-input-number v-model="duration" :min="5" :max="600" :step="5"
                       style="width:140px" />
      <span style="margin:0 8px">秒</span>
      <el-button type="primary" :loading="running" @click="startCapture">
        {{ running ? '抓包中...' : '开始抓包' }}
      </el-button>
      <el-progress v-if="running" :percentage="capturePercent"
                   :stroke-width="10" style="flex:1;margin-left:20px" />
    </section>

    <!-- ── stat cards ──────────────────────────────── -->
    <el-row :gutter="16" style="margin-bottom:16px">
      <el-col :span="6" v-for="card in cards" :key="card.label">
        <div class="stat-card" :class="{ danger: card.danger }">
          <div class="card-label">{{ card.label }}</div>
          <div class="card-value">{{ card.value }}</div>
        </div>
      </el-col>
    </el-row>

    <!-- ── charts row ──────────────────────────────── -->
    <el-row :gutter="16" style="margin-bottom:16px">
      <el-col :span="10">
        <div class="chart-box">
          <h3>协议分布</h3>
          <v-chart :option="pieOption" autoresize style="height:320px" />
        </div>
      </el-col>
      <el-col :span="14">
        <div class="chart-box">
          <h3>告警列表</h3>
          <div style="margin-bottom:8px">
            <el-select v-model="severityFilter" placeholder="全部等级"
                       clearable size="small" style="width:120px">
              <el-option label="high" value="high" />
              <el-option label="medium" value="medium" />
              <el-option label="low" value="low" />
            </el-select>
          </div>
          <el-table :data="filteredAlerts" stripe max-height="280"
                    style="width:100%">
            <el-table-column prop="timestamp" label="时间" width="180" />
            <el-table-column prop="type" label="类型" width="130" />
            <el-table-column label="等级" width="90">
              <template #default="{ row }">
                <el-tag :type="tagType(row.severity)" size="small">
                  {{ row.severity }}
                </el-tag>
              </template>
            </el-table-column>
            <el-table-column prop="detail" label="详情" show-overflow-tooltip />
          </el-table>
        </div>
      </el-col>
    </el-row>

    <!-- ── timeline ────────────────────────────────── -->
    <div class="chart-box" style="margin-bottom:20px">
      <h3>流量时序</h3>
      <v-chart :option="timelineOption" autoresize style="height:260px" />
    </div>
  </div>
</template>

<script setup>
import { ref, computed, onMounted, onUnmounted } from 'vue'
import axios from 'axios'

// ── state ──────────────────────────────────────────
const duration = ref(60)
const running = ref(false)
const currentTime = ref('')
const severityFilter = ref('')
const summary = ref({})
const protocolStats = ref({})
const alerts = ref([])
const timeSeries = ref([])

let clockTimer = null
let progressTimer = null

// ── computed ───────────────────────────────────────
const cards = computed(() => [
  { label: '总包数', value: summary.value.total_packets ?? '-', danger: false },
  {
    label: '总告警数',
    value: summary.value.alert_count ?? alerts.value.length ?? '-',
    danger: alerts.value.length > 0,
  },
  {
    label: '规则命中',
    value: summary.value.rule_alert_count ?? '-',
    danger: (summary.value.rule_alert_count ?? 0) > 0,
  },
  {
    label: 'ML 异常',
    value: summary.value.ml_alert_count ?? '-',
    danger: (summary.value.ml_alert_count ?? 0) > 0,
  },
])

const filteredAlerts = computed(() => {
  if (!severityFilter.value) return alerts.value
  return alerts.value.filter(a => a.severity === severityFilter.value)
})

const capturePercent = computed(() => {
  const t = summary.value._progress ?? 0
  const total = duration.value || 1
  return Math.round((t / total) * 100)
})

const pieOption = computed(() => {
  const data = Object.entries(protocolStats.value).map(([name, value]) => ({
    name, value,
  }))
  return {
    backgroundColor: 'transparent',
    tooltip: { trigger: 'item', formatter: '{b}: {c} ({d}%)' },
    series: [{
      type: 'pie',
      radius: ['40%', '70%'],
      label: { color: '#ccc' },
      data,
      itemStyle: { borderColor: '#0a0e17', borderWidth: 2 },
    }],
  }
})

const timelineOption = computed(() => {
  const ts = timeSeries.value
  if (!ts.length) return { backgroundColor: 'transparent' }
  const time = ts.map(t => t.time)
  const protos = ['TCP', 'UDP', 'DNS', 'ICMP']
  return {
    backgroundColor: 'transparent',
    tooltip: { trigger: 'axis' },
    legend: { data: protos, textStyle: { color: '#aaa' } },
    grid: { left: 50, right: 20, bottom: 30, top: 40 },
    xAxis: { type: 'category', data: time, axisLabel: { color: '#888' } },
    yAxis: { type: 'value', axisLabel: { color: '#888' } },
    series: protos.map(p => ({
      name: p,
      type: 'line',
      stack: 'total',
      areaStyle: { opacity: 0.6 },
      data: ts.map(t => t[p] ?? 0),
    })),
  }
})

// ── helpers ────────────────────────────────────────
function tagType(severity) {
  return { high: 'danger', medium: 'warning', low: 'info' }[severity] || ''
}

function updateTime() {
  currentTime.value = new Date().toLocaleTimeString()
}

// ── actions ────────────────────────────────────────
async function startCapture() {
  try {
    running.value = true
    const { data } = await axios.post('/api/capture', {
      duration: duration.value,
      interface: null,
    })
    const pcapName = data.pcap_file.split('/').pop()

    // progress polling
    let elapsed = 0
    progressTimer = setInterval(() => {
      elapsed += 1
      summary.value._progress = elapsed
      if (elapsed >= duration.value) clearInterval(progressTimer)
    }, 1000)

    // wait for capture to finish, then analyse
    const wait = duration.value * 1000 + 3000
    setTimeout(() => {
      clearInterval(progressTimer)
      analyze(pcapName)
    }, wait)
  } catch (e) {
    running.value = false
    console.error(e)
  }
}

async function analyze(pcapName) {
  try {
    const { data } = await axios.get(`/api/analyze/${pcapName}`)
    summary.value = data.summary
    summary.value.alert_count = data.alert_count
    summary.value.rule_alert_count = data.rule_alert_count
    summary.value.ml_alert_count = data.ml_alert_count
    protocolStats.value = data.protocol_stats
    alerts.value = data.alerts
  } catch (e) {
    console.error(e)
  } finally {
    running.value = false
  }
}

async function pollStats() {
  try {
    const { data } = await axios.get('/api/stats')
    if (data.status === 'ok') {
      summary.value = data.summary
      summary.value.alert_count = data.alert_count
      summary.value.rule_alert_count = data.rule_alert_count
      summary.value.ml_alert_count = data.ml_alert_count
      protocolStats.value = data.protocol_stats
      running.value = data.capture_running
    }
  } catch { /* ignore */ }
}

// ── lifecycle ──────────────────────────────────────
onMounted(() => {
  updateTime()
  clockTimer = setInterval(updateTime, 1000)
  setInterval(pollStats, 30000)
})

onUnmounted(() => {
  clearInterval(clockTimer)
  clearInterval(progressTimer)
})
</script>

<style scoped>
.dashboard { padding: 16px 24px; }

.nav-bar {
  display: flex; justify-content: space-between; align-items: center;
  margin-bottom: 20px; padding-bottom: 12px;
  border-bottom: 1px solid #1e2a3a;
}
.nav-bar h1 { margin: 0; font-size: 20px; }
.nav-right { display: flex; align-items: center; gap: 12px; color: #888; }
.clock { font-family: monospace; }

.status-dot {
  width: 10px; height: 10px; border-radius: 50%; background: #555;
  display: inline-block;
}
.status-dot.active { background: #67c23a; box-shadow: 0 0 6px #67c23a; }

.controls {
  display: flex; align-items: center; margin-bottom: 20px;
}

.stat-card {
  background: #111827; border: 1px solid #1e2a3a; border-radius: 8px;
  padding: 16px; text-align: center;
}
.stat-card.danger { border-color: #f56c6c; }
.card-label { color: #888; font-size: 13px; margin-bottom: 6px; }
.card-value { font-size: 28px; font-weight: 700; }

.chart-box {
  background: #111827; border: 1px solid #1e2a3a; border-radius: 8px;
  padding: 16px;
}
.chart-box h3 { margin: 0 0 12px 0; font-size: 14px; color: #aaa; }
</style>
