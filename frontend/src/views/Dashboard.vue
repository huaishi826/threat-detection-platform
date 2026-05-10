<template>
  <div class="dashboard">
    <!-- top nav -->
    <header class="nav-bar">
      <div class="nav-brand">
        <LogoIcon />
        <span class="brand-text">ThreatSight</span>
        <el-tag v-if="isDemo && hasData" type="warning" size="small" effect="dark" style="margin-left:8px">DEMO</el-tag>
      </div>
      <div class="nav-right">
        <router-link to="/history" class="nav-link">📋 历史记录</router-link>
        <router-link to="/settings" class="nav-link">⚙️ 设置</router-link>
        <div class="health-status" :class="{ healthy: healthOk === true, unhealthy: healthOk === false }">
          <span class="status-dot" />
          <span class="status-text">{{ healthOk === null ? '检测中...' : healthOk ? '系统运行正常' : '系统异常' }}</span>
        </div>
        <span class="clock">{{ currentTime }}</span>
      </div>
    </header>

    <!-- capture controls -->
    <section class="controls">
      <el-input-number v-model="duration" :min="5" :max="600" :step="5"
                       size="large" style="width:140px" :disabled="running" />
      <span style="margin:0 8px;color:#94a3b8">秒</span>
      <el-button
        type="primary"
        size="large"
        round
        :loading="running"
        :disabled="running"
        @click="startCapture"
      >
        <el-icon v-if="!running" style="margin-right:6px"><VideoCamera /></el-icon>
        {{ running ? statusText : '开始抓包' }}
      </el-button>
      <el-progress v-if="running" :percentage="capturePercent"
                   :stroke-width="10" :show-text="false"
                   :color="analyzing ? '#8b5cf6' : '#3b82f6'"
                   style="flex:1;margin-left:20px" />
      <el-button
        v-if="hasData"
        type="success"
        size="large"
        round
        plain
        :loading="exporting"
        @click="exportPDF"
        style="margin-left:16px"
      >
        📄 导出 PDF
      </el-button>
    </section>

    <!-- capture error -->
    <el-alert
      v-if="captureError"
      :title="captureError"
      type="error"
      show-icon
      closable
      @close="captureError = ''"
      style="margin-bottom:16px"
    />

    <!-- result toast -->
    <transition name="slide-down">
      <div v-if="resultToast.show" class="result-toast" :class="resultToast.type">
        <span>{{ resultToast.type === 'success' ? '✅' : '⚠️' }}</span>
        <span>{{ resultToast.message }}</span>
      </div>
    </transition>

    <!-- empty state -->
    <div v-if="!hasData && !running" class="empty-state">
      <div class="empty-icon">📡</div>
      <div class="empty-text">暂无监控数据，请点击上方按钮开始抓包</div>
    </div>

    <!-- report area (captured by html2canvas) -->
    <div ref="reportArea">
      <!-- stat cards -->
      <el-row v-if="hasData || running" :gutter="16" style="margin-bottom:16px">
        <el-col :span="6" v-for="card in cards" :key="card.label">
          <div class="stat-card" :class="{ danger: card.danger }">
            <div class="card-label">{{ card.label }}</div>
            <div class="card-value">{{ card.value }}</div>
          </div>
        </el-col>
      </el-row>

      <!-- charts row -->
      <el-row v-if="hasData" :gutter="16" style="margin-bottom:16px">
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
              <el-table-column label="时间" width="180">
                <template #default="{ row }">
                  {{ formatTime(row.timestamp) }}
                </template>
              </el-table-column>
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

      <!-- timeline -->
      <div v-if="hasData" class="chart-box" style="margin-bottom:20px">
        <h3>流量时序</h3>
        <v-chart :option="timelineOption" autoresize style="height:260px" />
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, computed, onMounted, onUnmounted } from 'vue'
import axios from 'axios'
import { VideoCamera } from '@element-plus/icons-vue'
import LogoIcon from '../components/LogoIcon.vue'

// state
const duration = ref(60)
const running = ref(false)
const analyzing = ref(false)
const statusText = ref('')
const currentTime = ref('')
const severityFilter = ref('')
const summary = ref({})
const protocolStats = ref({})
const alerts = ref([])
const timeSeries = ref([])
const healthOk = ref(null)
const exporting = ref(false)
const reportArea = ref(null)
const isDemo = ref(false)  // whether showing demo data
const resultToast = ref({ show: false, message: '', type: 'success' })  // result notification
const captureError = ref('')  // capture-level error message

// Time formatting: parse UTC timestamp to local readable string
function formatTime(iso) {
  if (!iso) return '-'
  // Handle non-ISO timestamps like "window_0", "0:00:05"
  if (typeof iso === 'string' && !iso.includes('T') && !iso.includes('-')) return iso
  let d = new Date(iso)
  // If no timezone info, treat as UTC
  if (isNaN(d.getTime()) && typeof iso === 'string' && !iso.includes('+') && !iso.endsWith('Z')) {
    d = new Date(iso + 'Z')
  }
  if (isNaN(d.getTime())) return iso  // fallback to raw string
  return d.toLocaleString('zh-CN', {
    year: 'numeric', month: '2-digit', day: '2-digit',
    hour: '2-digit', minute: '2-digit', second: '2-digit',
  })
}

let clockTimer = null
let progressTimer = null
let healthTimer = null
let progressPollTimer = null  // backend progress polling
let statsTimer = null  // stats polling

// computed
const hasData = computed(() => {
  return Object.keys(protocolStats.value).length > 0 || alerts.value.length > 0
})

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
  if (analyzing.value) return 100
  const elapsed = summary.value._progress ?? 0
  const total = duration.value || 1
  return Math.round((elapsed / total) * 100)
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
      itemStyle: { borderColor: '#0f172a', borderWidth: 2 },
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

// helpers
function tagType(severity) {
  return { high: 'danger', medium: 'warning', low: 'info' }[severity] || ''
}

function updateTime() {
  currentTime.value = new Date().toLocaleTimeString()
}

// health check
async function checkHealth() {
  try {
    const resp = await axios.get('/api/health', { timeout: 5000 })
    healthOk.value = resp.status === 200 && resp.data.status === 'ok'
  } catch {
    healthOk.value = false
  }
}

// actions
async function startCapture() {
  try {
    running.value = true
    analyzing.value = false
    captureError.value = ''
    statusText.value = '正在启动抓包...'
    const { data: capData } = await axios.post('/api/capture', {
      duration: duration.value,
      interface: null,
    })
    const pcapName = capData.pcap_file.split(/[\\/]/).pop()
    if (!pcapName) {
      captureError.value = '抓包启动失败：未获取到文件名'
      running.value = false
      return
    }
    statusText.value = '抓包中...'

    // Poll backend progress instead of fake counter
    clearInterval(progressPollTimer)
    progressPollTimer = setInterval(async () => {
      try {
        const { data: prog } = await axios.get('/api/capture/progress', { timeout: 3000 })
        summary.value._progress = prog.elapsed
        // Check for capture-level error
        if (prog.capture_error) {
          clearInterval(progressPollTimer)
          captureError.value = '抓包错误: ' + prog.capture_error
          statusText.value = '抓包失败'
          running.value = false
          return
        }
        if (!prog.running) {
          clearInterval(progressPollTimer)
          // Capture finished — start analysis
          statusText.value = '分析中...'
          analyzing.value = true
          await analyze(pcapName)
        }
      } catch { /* ignore poll errors */ }
    }, 1500)

  } catch (e) {
    running.value = false
    analyzing.value = false
    captureError.value = '抓包启动失败: ' + (e.response?.data?.error || e.message || '请检查是否以管理员权限运行')
    statusText.value = '抓包失败'
    console.error(e)
  }
}

async function analyze(pcapName) {
  try {
    // 300s timeout for large pcap files
    const { data } = await axios.get('/api/analyze/' + pcapName, { timeout: 300000 })
    if (data.status === 'ok') {
      summary.value = data.summary
      summary.value.alert_count = data.alert_count
      summary.value.rule_alert_count = data.rule_alert_count
      summary.value.ml_alert_count = data.ml_alert_count
      protocolStats.value = data.protocol_stats
      alerts.value = data.alerts
      timeSeries.value = data.time_series || []
      isDemo.value = false
      statusText.value = '分析完成'
      // Show result notification
      const msg = data.message || `完成：${data.total_packets || 0} 包，${data.alert_count || 0} 告警`
      resultToast.value = { show: true, message: msg, type: data.alert_count > 0 ? 'warning' : 'success' }
      setTimeout(() => { resultToast.value.show = false }, 5000)
    } else {
      statusText.value = '分析失败: ' + (data.error || '未知错误')
      captureError.value = statusText.value
    }
  } catch (e) {
    const msg = e.response?.data?.error
    statusText.value = '分析失败: ' + (msg || e.message || '网络超时，请重试')
    captureError.value = statusText.value
    console.error(e)
  } finally {
    running.value = false
    analyzing.value = false
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
      alerts.value = data.alerts || []
      timeSeries.value = data.time_series || []
      running.value = data.capture_running
      isDemo.value = data.is_demo || false
    }
  } catch { /* ignore */ }
}

// PDF export
async function exportPDF() {
  if (!reportArea.value) return
  exporting.value = true
  try {
    const html2canvas = (await import('html2canvas')).default
    const { jsPDF } = await import('jspdf')

    const canvas = await html2canvas(reportArea.value, {
      backgroundColor: '#0f172a',
      scale: 2,
      useCORS: true,
    })

    const pdf = new jsPDF('landscape', 'mm', 'a4')
    const pageW = pdf.internal.pageSize.getWidth()
    const pageH = pdf.internal.pageSize.getHeight()
    const imgW = pageW - 20  // 10mm margin each side
    const imgH = (canvas.height * imgW) / canvas.width

    // Title
    pdf.setFontSize(16)
    pdf.setTextColor(59, 130, 246)
    pdf.text('ThreatSight — Threat Detection Report', 10, 12)
    pdf.setFontSize(10)
    pdf.setTextColor(100)
    pdf.text(new Date().toLocaleString('zh-CN'), 10, 18)

    // Screenshot
    const imgData = canvas.toDataURL('image/png')
    pdf.addImage(imgData, 'PNG', 10, 22, imgW, Math.min(imgH, pageH - 25))

    // Filename
    const ts = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19)
    pdf.save(`ThreatSight_报告_${ts}.pdf`)
  } catch (e) {
    console.error('PDF export failed:', e)
  } finally {
    exporting.value = false
  }
}

// lifecycle
onMounted(() => {
  updateTime()
  clockTimer = setInterval(updateTime, 1000)
  pollStats()  // Load data immediately on page open
  statsTimer = setInterval(pollStats, 30000)
  checkHealth()
  healthTimer = setInterval(checkHealth, 10000)
})

onUnmounted(() => {
  clearInterval(clockTimer)
  clearInterval(progressPollTimer)
  clearInterval(healthTimer)
  clearInterval(statsTimer)
})
</script>

<style scoped>
.dashboard {
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
  gap: 10px;
}
.brand-text {
  font-size: 22px;
  font-weight: 700;
  font-family: 'Segoe UI', 'PingFang SC', sans-serif;
  background: linear-gradient(135deg, #3b82f6, #8b5cf6);
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
  background-clip: text;
}

.nav-right {
  display: flex;
  align-items: center;
  gap: 16px;
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

.health-status {
  display: flex;
  align-items: center;
  gap: 8px;
  font-size: 13px;
  color: #94a3b8;
}
.status-dot {
  width: 10px;
  height: 10px;
  border-radius: 50%;
  background: #475569;
  transition: all 0.3s ease;
}
.health-status.healthy .status-dot {
  background: #22c55e;
  box-shadow: 0 0 8px #22c55e;
  animation: breathe 2s ease-in-out infinite;
}
.health-status.unhealthy .status-dot {
  background: #ef4444;
  box-shadow: 0 0 8px #ef4444;
  animation: breathe 1.5s ease-in-out infinite;
}
.health-status.healthy .status-text { color: #86efac; }
.health-status.unhealthy .status-text { color: #fca5a5; }

@keyframes breathe {
  0%, 100% { opacity: 1; transform: scale(1); }
  50%      { opacity: 0.6; transform: scale(0.85); }
}

.clock {
  font-family: 'JetBrains Mono', monospace;
  color: #64748b;
  font-size: 13px;
}

.controls {
  display: flex;
  align-items: center;
  margin-bottom: 20px;
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
}

.stat-card {
  background: #1e293b;
  border: 1px solid #334155;
  border-radius: 10px;
  padding: 18px;
  text-align: center;
  transition: border-color 0.2s;
}
.stat-card.danger {
  border-color: #ef4444;
  box-shadow: 0 0 12px rgba(239, 68, 68, 0.15);
}
.card-label {
  color: #94a3b8;
  font-size: 13px;
  margin-bottom: 6px;
}
.card-value {
  font-size: 28px;
  font-weight: 700;
  color: #f1f5f9;
}

.chart-box {
  background: #1e293b;
  border: 1px solid #334155;
  border-radius: 10px;
  padding: 16px;
}
.chart-box h3 {
  margin: 0 0 12px 0;
  font-size: 14px;
  color: #94a3b8;
}

/* result toast */
.result-toast {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 12px 20px;
  border-radius: 10px;
  margin-bottom: 16px;
  font-size: 14px;
  font-weight: 600;
}
.result-toast.success {
  background: rgba(34, 197, 94, 0.12);
  border: 1px solid rgba(34, 197, 94, 0.3);
  color: #86efac;
}
.result-toast.warning {
  background: rgba(251, 191, 36, 0.12);
  border: 1px solid rgba(251, 191, 36, 0.3);
  color: #fde68a;
}

.slide-down-enter-active {
  transition: all 0.35s ease;
}
.slide-down-leave-active {
  transition: all 0.25s ease;
}
.slide-down-enter-from {
  opacity: 0;
  transform: translateY(-12px);
}
.slide-down-leave-to {
  opacity: 0;
}
</style>
