const API = import.meta.env.VITE_API_BASE_URL || '/api'

async function request(path, options = {}) {
  const response = await fetch(`${API}${path}`, {
    headers: { 'Content-Type': 'application/json', ...(options.headers || {}) },
    ...options,
  })

  const text = await response.text()
  let data = null

  try {
    data = text ? JSON.parse(text) : null
  } catch {
    data = text
  }

  if (!response.ok) {
    throw new Error(
      data?.detail || text || `HTTP ${response.status}`
    )
  }

  return data
}

export const api = {
  events: () => request('/events'),
  users: () => request('/users'),

  createUser: payload =>
    request('/users', {
      method: 'POST',
      body: JSON.stringify(payload)
    }),

  setUserEnabled: (username, enabled) =>
    request(
      `/users/${encodeURIComponent(username)}/${enabled ? 'enable' : 'disable'}`,
      { method: 'POST' }
    ),

  deleteUser: username =>
    request(`/users/${encodeURIComponent(username)}`, {
      method: 'DELETE'
    }),

  behaviorProfile: username =>
    request(`/users/${encodeURIComponent(username)}/behavior-profile`),

  dynamicRisk: username =>
    request(`/users/${encodeURIComponent(username)}/dynamic-risk`),

  endpointProfile: username =>
    request(`/users/${encodeURIComponent(username)}/endpoint-profile`),

  incidents: () => request('/incidents'),
  incident: id => request(`/incidents/${id}`),

  riskExplanation: eventId =>
    request(`/events/${eventId}/risk-explanation`),

  eventAI: eventId =>
    request(`/ai-analysis/${eventId}`, {
      method: 'POST'
    }),

  incidentAI: id =>
    request(`/ai-analysis/incident/${id}`, {
      method: 'POST'
    }),

  behaviorChanges: (params = {}) => {
    const q = new URLSearchParams()

    Object.entries(params).forEach(([k, v]) => {
      if (
        v != null &&
        v !== '' &&
        v !== '전체'
      ) {
        q.set(k, v)
      }
    })

    return request(
      `/behavior-changes${q.toString() ? `?${q}` : ''}`
    )
  },

  behaviorDecision: (id, action, note = null) =>
    request(`/behavior-changes/${id}/decision`, {
      method: 'POST',
      body: JSON.stringify({ action, note })
    }),

  playbook: id =>
    request(`/incidents/${id}/playbook`),

  playbookStep: (
    incidentId,
    stepId,
    action,
    note = null
  ) =>
    request(
      `/incidents/${incidentId}/playbook/steps/${stepId}`,
      {
        method: 'POST',
        body: JSON.stringify({ action, note })
      }
    ),

  demoNormal: () =>
    request('/demo/normal', {
      method: 'POST'
    }),

  demoAttack: () =>
    request('/demo/attack', {
      method: 'POST'
    }),

  demoReset: () =>
    request('/demo/reset-siem-demo', {
      method: 'POST'
    }),

  adaptiveCompare: () =>
    request('/demo/compare-adaptive-baseline', {
      method: 'POST'
    }),
}


