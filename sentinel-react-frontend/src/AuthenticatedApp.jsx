import { useEffect, useState } from 'react'
import Dashboard from './App.jsx'

const API = import.meta.env.VITE_API_BASE_URL || '/api'

// 기존 Dashboard 내부 fetch들도 로그인 쿠키를 보내도록 기본값 적용
const nativeFetch = window.fetch.bind(window)

if (!window.__sentinelCredentialFetchInstalled) {
  window.fetch = (input, init = {}) => {
    return nativeFetch(input, {
      credentials: 'include',
      ...init,
    })
  }

  window.__sentinelCredentialFetchInstalled = true
}

function LoginScreen({ onLogin }) {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

  const submit = async (event) => {
    event.preventDefault()

    if (!username.trim() || !password) {
      setError('아이디와 비밀번호를 입력하세요.')
      return
    }

    setLoading(true)
    setError('')

    try {
      const response = await fetch(`${API}/auth/login`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        credentials: 'include',
        body: JSON.stringify({
          username: username.trim(),
          password,
        }),
      })

      const data = await response.json().catch(() => ({}))

      if (!response.ok) {
        throw new Error(
          data.detail || '로그인에 실패했습니다.'
        )
      }

      onLogin(data.username || username.trim())
    } catch (err) {
      setError(
        err?.message || '인증 서버에 연결할 수 없습니다.'
      )
    } finally {
      setLoading(false)
    }
  }

  return (
    <main className="sentinel-login">
      <div className="sentinel-login-glow sentinel-login-glow-a" />
      <div className="sentinel-login-glow sentinel-login-glow-b" />

      <section className="sentinel-login-content">
        <div className="sentinel-login-brand">
          SENTINEL
        </div>

        <h1>Security Operations Center</h1>

        <p className="sentinel-login-description">
          사용자 행위 분석, 이상행동 탐지 및 보안 사고 대응을 위한
          통합 보안 관제 플랫폼
        </p>

        <form
          className="sentinel-login-form"
          onSubmit={submit}
        >
          <label>
            <span>Administrator ID</span>
            <input
              autoFocus
              autoComplete="username"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              placeholder="관리자 계정"
            />
          </label>

          <label>
            <span>Password</span>
            <input
              type="password"
              autoComplete="current-password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="비밀번호"
            />
          </label>

          {error && (
            <div className="sentinel-login-error">
              {error}
            </div>
          )}

          <button
            className="sentinel-login-button"
            type="submit"
            disabled={loading}
          >
            {loading ? '인증 중…' : '로그인'}
          </button>
        </form>

        <div className="sentinel-login-security">
          <span className="sentinel-login-dot" />
          Authorized personnel only
        </div>

        <div className="sentinel-login-footer">
          SENTINEL · SIEM / UEBA Security Platform
        </div>
      </section>
    </main>
  )
}

function AuthLoading() {
  return (
    <main className="sentinel-auth-loading">
      <div className="sentinel-auth-wordmark">
        SENTINEL
      </div>
      <div className="sentinel-auth-spinner" />
    </main>
  )
}

export default function AuthenticatedApp() {
  const [state, setState] = useState({
    checking: true,
    authenticated: false,
    username: '',
  })

  useEffect(() => {
    let active = true

    const check = async () => {
      try {
        const response = await fetch(
          `${API}/auth/me`,
          {
            credentials: 'include',
          }
        )

        if (!active) return

        if (response.ok) {
          const data = await response.json()

          setState({
            checking: false,
            authenticated: true,
            username: data.username || 'admin',
          })
        } else {
          setState({
            checking: false,
            authenticated: false,
            username: '',
          })
        }
      } catch {
        if (!active) return

        setState({
          checking: false,
          authenticated: false,
          username: '',
        })
      }
    }

    check()

    return () => {
      active = false
    }
  }, [])

  const login = (username) => {
    setState({
      checking: false,
      authenticated: true,
      username,
    })
  }

  const logout = async () => {
    try {
      await fetch(
        `${API}/auth/logout`,
        {
          method: 'POST',
          credentials: 'include',
        }
      )
    } catch {
      // 서버 응답이 없어도 프론트에서는 로그인 화면으로 복귀
    }

    setState({
      checking: false,
      authenticated: false,
      username: '',
    })
  }

  if (state.checking) {
    return <AuthLoading />
  }

  if (!state.authenticated) {
    return <LoginScreen onLogin={login} />
  }

  return (
    <div className="sentinel-authenticated-shell">
      <Dashboard />

      <div className="sentinel-session-control">
        <span className="sentinel-session-status">
          <span className="sentinel-session-dot" />
          {state.username}
        </span>

        <button
          type="button"
          onClick={logout}
          className="sentinel-logout-button"
        >
          로그아웃
        </button>
      </div>
    </div>
  )
}
