<script setup>
import { computed, onMounted, onUnmounted, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'

const route = useRoute()
const router = useRouter()
const token = ref(localStorage.getItem('syncbox-token') || '')
const files = ref([])
const currentPath = ref('')
const loading = ref(false)
const error = ref('')
const status = ref('connecting')
const uploadProgress = ref(0)
const uploading = ref(false)
const picker = ref(null)
let source

const crumbs = computed(() => currentPath.value ? currentPath.value.split('/').filter(Boolean) : [])
const totalBytes = computed(() => files.value.filter(file => !file.isDir).reduce((sum, file) => sum + file.size, 0))
const formatSize = bytes => {
  if (bytes < 1024) return `${bytes} B`
  const units = ['KB', 'MB', 'GB', 'TB']
  let value = bytes / 1024, index = 0
  while (value >= 1024 && index < units.length - 1) { value /= 1024; index++ }
  return `${value.toFixed(value < 10 ? 1 : 0)} ${units[index]}`
}
const dateLabel = value => new Intl.DateTimeFormat('en', { month: 'short', day: 'numeric', year: 'numeric' }).format(new Date(value))
const icon = file => file.isDir ? 'folder' : (file.name.split('.').pop() || 'file').toLowerCase()

function setToken() {
  localStorage.setItem('syncbox-token', token.value.trim())
  connectEvents()
  loadFiles()
}
async function request(url, options = {}) {
  const response = await fetch(url, { ...options, headers: { Authorization: `Bearer ${token.value}`, ...options.headers } })
  if (!response.ok) throw new Error((await response.text()) || `Request failed (${response.status})`)
  return response
}
async function loadFiles() {
  loading.value = true; error.value = ''
  try {
    const query = currentPath.value ? `?path=${encodeURIComponent(currentPath.value)}` : ''
    const data = await (await request(`/api/files${query}`)).json()
    files.value = data.files || []
  } catch (err) { error.value = err.message }
  finally { loading.value = false }
}
function navigate(path) {
  currentPath.value = path
  router.push(path ? `/${path.split('/').map(encodeURIComponent).join('/')}` : '/')
  loadFiles()
}
function openItem(file) {
  if (file.isDir) navigate(currentPath.value ? `${currentPath.value}/${file.name}` : file.name)
  else download(file)
}
async function download(file) {
  try {
    const response = await request(`/api/download?path=${encodeURIComponent(file.path)}`)
    const blob = await response.blob()
    const url = URL.createObjectURL(blob)
    const anchor = document.createElement('a'); anchor.href = url; anchor.download = file.name; anchor.click()
    URL.revokeObjectURL(url)
  } catch (err) { error.value = err.message }
}
function uploadFiles(event) {
  const selected = [...(event.target.files || [])]
  if (!selected.length) return
  const body = new FormData()
  selected.forEach(file => body.append('files', file))
  const query = currentPath.value ? `?path=${encodeURIComponent(currentPath.value)}` : ''
  const xhr = new XMLHttpRequest(); uploading.value = true; uploadProgress.value = 0
  xhr.open('POST', `/api/upload${query}`); xhr.setRequestHeader('Authorization', `Bearer ${token.value}`)
  xhr.upload.onprogress = event => { if (event.lengthComputable) uploadProgress.value = Math.round(event.loaded / event.total * 100) }
  xhr.onload = () => {
    uploading.value = false; picker.value.value = ''
    if (xhr.status >= 200 && xhr.status < 300) loadFiles()
    else error.value = xhr.responseText || `Upload failed (${xhr.status})`
  }
  xhr.onerror = () => { uploading.value = false; error.value = 'Upload connection failed' }
  xhr.send(body)
}
function connectEvents() {
  source?.close(); status.value = token.value ? 'connecting' : 'offline'
  if (!token.value) return
  // EventSource cannot set Authorization headers; pass the token in the query only for the SSE stream.
  source = new EventSource(`/api/events?access_token=${encodeURIComponent(token.value)}`)
  source.addEventListener('status', () => { status.value = 'live' })
  source.onopen = () => { status.value = 'live' }
  source.onerror = () => { status.value = 'reconnecting' }
}
function goToCrumb(index) { navigate(crumbs.value.slice(0, index + 1).join('/')) }
watch(() => route.fullPath, value => {
  const raw = value.replace(/^\//, '')
  try { currentPath.value = decodeURIComponent(raw).replace(/\/$/, '') } catch { currentPath.value = raw }
})
onMounted(() => { connectEvents(); if (token.value) loadFiles() })
onUnmounted(() => source?.close())
</script>

<template>
  <div class="app-shell">
    <aside class="rail">
      <a class="brand-mark" href="/" aria-label="Syncbox home"><span class="mark-core"></span></a>
      <div class="rail-rule"></div>
      <button class="rail-action active" aria-label="Files" title="Files"><svg viewBox="0 0 24 24"><path d="M3.5 6.5h6l2 2h9v9.7a1.8 1.8 0 0 1-1.8 1.8H5.3a1.8 1.8 0 0 1-1.8-1.8z"/><path d="M3.5 9h17"/></svg></button>
      <div class="rail-bottom"><span class="rail-dot"></span><span class="rail-version">v0.1</span></div>
    </aside>

    <main class="workspace">
      <header class="topbar">
        <div class="topbar-context"><span class="eyebrow">PERSONAL CLOUD</span><span class="context-divider">/</span><span class="context-label">Workspace</span></div>
        <div class="topbar-right"><span class="sync-status" :class="status"><i></i>{{ status === 'live' ? 'SYNC LIVE' : status.toUpperCase() }}</span><button class="avatar" title="Syncbox workspace">S</button></div>
      </header>

      <section class="content">
        <div class="welcome-line"><span class="welcome-rule"></span><span>YOUR FILES, IN THEIR PLACE</span></div>
        <div class="heading-row"><div><h1>File<br class="mobile-break"> <em>workspace.</em></h1><p class="lede">A quiet place for everything you keep.</p></div><div class="space-card"><span class="space-label">IN THIS FOLDER</span><strong>{{ files.filter(file => !file.isDir).length }} <small>FILES</small></strong><span class="space-meta">{{ formatSize(totalBytes) }} total</span></div></div>

        <div class="toolbar">
          <nav class="breadcrumbs" aria-label="Breadcrumb">
            <button @click="navigate('')">Workspace</button><template v-for="(crumb, index) in crumbs" :key="`${crumb}-${index}`"><span class="crumb-slash">/</span><button :class="{ current: index === crumbs.length - 1 }" @click="goToCrumb(index)">{{ crumb }}</button></template>
          </nav>
          <div class="toolbar-actions"><button class="icon-button" title="Refresh" aria-label="Refresh files" @click="loadFiles"><svg viewBox="0 0 24 24"><path d="M20 7v5h-5M4 17v-5h5"/><path d="M5.6 9a7 7 0 0 1 11.8-2L20 12M4 12l2.6 5a7 7 0 0 0 11.8-2"/></svg></button><button class="upload-button" @click="picker?.click()"><span>+</span> Upload files</button><input ref="picker" class="visually-hidden" type="file" multiple @change="uploadFiles" /></div>
        </div>

        <div v-if="uploading" class="upload-progress"><div class="progress-copy"><span>UPLOADING YOUR FILES</span><strong>{{ uploadProgress }}%</strong></div><div class="progress-track"><span :style="{ width: `${uploadProgress}%` }"></span></div></div>
        <div v-if="error" class="error-banner"><span>{{ error }}</span><button @click="error = ''">Dismiss</button></div>

        <div class="list-heading"><span class="col-name">NAME <span class="sort-mark">↓</span></span><span class="col-modified">LAST MODIFIED</span><span class="col-size">SIZE</span><span class="col-more"></span></div>
        <div v-if="loading" class="empty-state"><span class="spinner"></span><span>Opening your workspace…</span></div>
        <div v-else-if="!files.length" class="empty-state"><span class="empty-orbit"><i></i></span><strong>No files here. Yet.</strong><span>Drop in a few things to get started.</span><button class="empty-upload" @click="picker?.click()">Choose files <span>↗</span></button></div>
        <div v-else class="file-list">
          <button v-for="(file, index) in files" :key="file.path" class="file-row" :style="{ '--row-index': index }" @click="openItem(file)"><span class="file-main"><span class="file-icon" :class="{ folder: file.isDir, [`ext-${icon(file)}`]: !file.isDir }"><svg v-if="file.isDir" viewBox="0 0 24 24"><path d="M3 6.5h7l2 2h9a1 1 0 0 1 1 1v8.7a1.8 1.8 0 0 1-1.8 1.8H4.8A1.8 1.8 0 0 1 3 18.2z"/></svg><svg v-else viewBox="0 0 24 24"><path d="M6 3.5h8l4.5 4.7v12.3H6z"/><path d="M14 3.5v5h4.5M9 13h6M9 16h6"/></svg></span><span class="file-name">{{ file.name }}</span><span v-if="file.isDir" class="folder-count">FOLDER</span></span><span class="file-date">{{ dateLabel(file.modTime) }}</span><span class="file-size">{{ file.isDir ? '—' : formatSize(file.size) }}</span><span class="file-more">↗</span></button>
        </div>
        <footer class="list-footer"><span><b>{{ files.length.toString().padStart(2, '0') }}</b> ITEMS IN VIEW</span><span>PRIVATE BY DESIGN <i>·</i> SYNCBOX</span></footer>

        <section class="token-panel"><label for="token">ACCESS TOKEN</label><input id="token" v-model="token" type="password" placeholder="Enter your bearer token" @keydown.enter="setToken" /><button @click="setToken">Connect <span>↗</span></button><small>Saved only in this browser.</small></section>
        <p class="footnote">SYNCBOX <span>—</span> FILES MOVE AT YOUR PACE</p>
      </section>
    </main>
  </div>
</template>
