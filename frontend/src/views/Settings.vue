<template>
  <div class="settings-page">
    <!-- top nav -->
    <header class="nav-bar">
      <div class="nav-brand">
        <LogoIcon />
        <span class="brand-text">ThreatSight</span>
      </div>
      <div class="nav-right">
        <router-link to="/" class="nav-link">🏠 仪表盘</router-link>
        <router-link to="/history" class="nav-link">📋 历史记录</router-link>
        <span class="clock">{{ currentTime }}</span>
      </div>
    </header>

    <h2 class="page-title">⚙️ 系统配置</h2>

    <!-- detection rules -->
    <el-card class="config-card" shadow="never">
      <template #header>
        <span class="card-title">🛡️ 检测规则配置</span>
      </template>

      <el-form label-position="left" label-width="140px" :model="form">
        <!-- SYN Flood -->
        <el-divider content-position="left">SYN Flood 检测</el-divider>
        <el-form-item label="窗口大小 (秒)">
          <el-input-number v-model="form.syn_flood.window" :min="1" :max="600" />
        </el-form-item>
        <el-form-item label="阈值 (0-1)">
          <el-input-number v-model="form.syn_flood.threshold" :min="0.01" :max="0.99" :step="0.05" />
        </el-form-item>
        <el-form-item label="最小包数">
          <el-input-number v-model="form.syn_flood.min_packets" :min="1" :max="100000" />
        </el-form-item>

        <!-- DNS Tunnel -->
        <el-divider content-position="left">DNS 隧道检测</el-divider>
        <el-form-item label="窗口大小 (秒)">
          <el-input-number v-model="form.dns_tunnel.window" :min="1" :max="600" />
        </el-form-item>
        <el-form-item label="查询次数阈值">
          <el-input-number v-model="form.dns_tunnel.query_threshold" :min="1" :max="10000" />
        </el-form-item>
        <el-form-item label="域名长度阈值">
          <el-input-number v-model="form.dns_tunnel.length_threshold" :min="1" :max="500" />
        </el-form-item>

        <!-- Port Scan -->
        <el-divider content-position="left">端口扫描检测</el-divider>
        <el-form-item label="窗口大小 (秒)">
          <el-input-number v-model="form.port_scan.window" :min="1" :max="600" />
        </el-form-item>
        <el-form-item label="端口数阈值">
          <el-input-number v-model="form.port_scan.port_threshold" :min="1" :max="65535" />
        </el-form-item>
      </el-form>
    </el-card>

    <!-- ML model -->
    <el-card class="config-card" shadow="never">
      <template #header>
        <span class="card-title">🤖 ML 模型配置</span>
      </template>

      <el-form label-position="left" label-width="140px" :model="form">
        <el-form-item label="污染率 (0-1)">
          <el-input-number v-model="form.ml.contamination" :min="0.01" :max="0.5" :step="0.01" />
          <span class="hint">越高 = 越多正常流量被标记为异常</span>
        </el-form-item>
      </el-form>
    </el-card>

    <!-- auto-response -->
    <el-card class="config-card" shadow="never">
      <template #header>
        <span class="card-title">🚨 自动化响应配置</span>
      </template>

      <el-form label-position="left" label-width="140px" :model="form">
        <el-form-item label="自动封禁">
          <el-switch v-model="form.auto_block.enabled" />
          <span class="hint">启用后高危攻击将自动阻断（需额外配置）</span>
        </el-form-item>

        <el-divider content-position="left">邮件告警</el-divider>
        <el-form-item label="邮件告警">
          <el-switch v-model="form.notification.email_enabled" />
        </el-form-item>
        <el-form-item label="告警邮箱">
          <el-input
            v-model="form.notification.email_to"
            placeholder="admin@example.com"
            :disabled="!form.notification.email_enabled"
            style="max-width: 360px"
          />
        </el-form-item>
      </el-form>
    </el-card>

    <!-- save button -->
    <div class="save-bar">
      <el-button type="primary" size="large" round :loading="saving" @click="saveConfig">
        💾 保存配置
      </el-button>
    </div>
  </div>
</template>

<script setup>
import { ref, reactive, onMounted, onUnmounted } from 'vue'
import axios from 'axios'
import { ElMessage } from 'element-plus'
import LogoIcon from '../components/LogoIcon.vue'

const currentTime = ref('')
const saving = ref(false)
let clockTimer = null

const form = reactive({
  syn_flood: { window: 10, threshold: 0.7, min_packets: 100 },
  dns_tunnel: { window: 60, query_threshold: 50, length_threshold: 40 },
  port_scan: { window: 30, port_threshold: 20 },
  ml: { contamination: 0.1 },
  auto_block: { enabled: false },
  notification: { email_enabled: false, email_to: '' },
})

function updateTime() {
  currentTime.value = new Date().toLocaleTimeString()
}

async function loadConfig() {
  try {
    const { data } = await axios.get('/api/config')
    Object.assign(form.syn_flood, data.syn_flood || {})
    Object.assign(form.dns_tunnel, data.dns_tunnel || {})
    Object.assign(form.port_scan, data.port_scan || {})
    Object.assign(form.ml, data.ml || {})
    Object.assign(form.auto_block, data.auto_block || {})
    Object.assign(form.notification, data.notification || {})
  } catch (e) {
    console.error('Failed to load config:', e)
    ElMessage.error('加载配置失败: ' + (e.message || '未知错误'))
  }
}

async function saveConfig() {
  saving.value = true
  try {
    const payload = JSON.parse(JSON.stringify(form))
    const { data } = await axios.post('/api/config', payload)
    if (data.status === 'ok') {
      ElMessage.success('配置已保存，下次检测将使用新阈值')
    } else {
      ElMessage.error(data.error || '保存失败')
    }
  } catch (e) {
    const msg = e.response?.data?.error || e.message || '未知错误'
    ElMessage.error('保存失败: ' + msg)
  } finally {
    saving.value = false
  }
}

onMounted(() => {
  loadConfig()
  updateTime()
  clockTimer = setInterval(updateTime, 1000)
})

onUnmounted(() => {
  clearInterval(clockTimer)
})
</script>

<style scoped>
.settings-page {
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
.clock {
  font-family: 'JetBrains Mono', monospace;
  color: #64748b;
  font-size: 13px;
}

.page-title {
  font-size: 20px;
  font-weight: 700;
  margin-bottom: 20px;
  color: #f1f5f9;
}

.config-card {
  background: #1e293b !important;
  border: 1px solid #334155 !important;
  border-radius: 10px;
  margin-bottom: 16px;
}
.card-title {
  font-size: 16px;
  font-weight: 600;
  color: #f1f5f9;
}

/* dark theme overrides for el-card header */
:deep(.el-card__header) {
  background: #0f172a;
  border-bottom: 1px solid #334155;
  padding: 14px 20px;
}
:deep(.el-card__body) {
  padding: 20px;
}

/* form labels */
:deep(.el-form-item__label) {
  color: #94a3b8 !important;
}

/* dividers */
:deep(.el-divider__text) {
  background: #1e293b;
  color: #64748b;
}
:deep(.el-divider) {
  border-color: #334155;
}

.hint {
  margin-left: 12px;
  font-size: 12px;
  color: #64748b;
}

.save-bar {
  display: flex;
  justify-content: center;
  padding: 24px 0 40px;
}
</style>
