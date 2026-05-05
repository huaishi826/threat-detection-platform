<template>
  <div class="logo-icon">
    <svg viewBox="0 0 36 36" width="36" height="36" fill="none">
      <!-- Shield -->
      <path
        d="M18 2 L32 9 V18 C32 26.5 26 32 18 35 C10 32 4 26.5 4 18 V9 Z"
        fill="url(#shield-grad)"
      />
      <!-- Lightning bolt -->
      <path
        d="M20 10 L14 20 H18 L15 28 L24 17 H19 Z"
        fill="#fff"
        opacity="0.95"
      />
      <defs>
        <linearGradient id="shield-grad" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stop-color="#3b82f6" />
          <stop offset="100%" stop-color="#1e40af" />
        </linearGradient>
      </defs>
    </svg>
  </div>
</template>

<script setup>
</script>

<style scoped>
.logo-icon {
  display: inline-flex;
  align-items: center;
  justify-content: center;
}
</style>
