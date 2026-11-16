from pathlib import Path
import shutil
import sys

ROOT = Path.cwd()
APP = ROOT / "sentinel-react-frontend" / "src" / "App.jsx"
CSS = ROOT / "sentinel-react-frontend" / "src" / "styles.css"

for p in (APP, CSS):
    if not p.exists():
        print(f"[ERROR] missing: {p}")
        print(r"C:\Users\김재경\PycharmProjects\siemueba 에서 실행하세요.")
        sys.exit(1)

for p in (APP, CSS):
    b = p.with_name(p.name + ".before_user_management_v6")
    if not b.exists():
        shutil.copy2(p, b)
        print(f"[BACKUP] {b.relative_to(ROOT)}")

app = APP.read_text(encoding="utf-8")
start = app.find("function UserAnalysisPage({events,users,refresh}){")
if start < 0:
    raise RuntimeError("UserAnalysisPage를 찾지 못했습니다.")

state_anchor = ",[deleteConfirm,setDeleteConfirm]=useState({})"
if "departmentFilter,setDepartmentFilter" not in app[start:]:
    pos = app.find(state_anchor, start)
    if pos < 0:
        raise RuntimeError("UserAnalysisPage state anchor를 찾지 못했습니다.")
    pos += len(state_anchor)
    extra_state = '''
  const[userSearch,setUserSearch]=useState('')
  const[departmentFilter,setDepartmentFilter]=useState('ALL')
  const[roleFilter,setRoleFilter]=useState('ALL')
  const[statusFilter,setStatusFilter]=useState('ALL')
  const[userPage,setUserPage]=useState(1)
'''
    app = app[:pos] + extra_state + app[pos:]
    print("[PATCH] 사용자 필터 state 추가")

anchor = "const learningCount=users.filter(u=>String(u.learning_status||'').toUpperCase()==='LEARNING').length"
if "const filteredUsers=users.filter" not in app[start:]:
    pos = app.find(anchor, start)
    if pos < 0:
        raise RuntimeError("learningCount anchor를 찾지 못했습니다.")
    pos += len(anchor)
    logic = r'''
  const departmentPresets=[
    'IT','개발','정보보안','인사','재무','영업',
    '기획','운영','법무','연구개발','경영지원','기타'
  ]
  const rolePresets=[
    'Backend Developer','Frontend Developer','Full-stack Developer',
    'Security Analyst','SOC Analyst','System Administrator',
    'Network Engineer','Data Analyst','Data Engineer',
    'Product Manager','Project Manager','HR','Finance','Sales',
    'Operations','Manager','Executive','기타'
  ]

  const departments=[...new Set([
    ...departmentPresets,
    ...users.map(u=>String(u.department||'').trim()).filter(Boolean)
  ])].sort((a,b)=>a.localeCompare(b,'ko'))

  const roles=[...new Set([
    ...rolePresets,
    ...users.map(u=>String(u.role||'').trim()).filter(Boolean)
  ])].sort((a,b)=>a.localeCompare(b,'ko'))

  const searchWord=userSearch.trim().toLowerCase()

  const filteredUsers=users.filter(u=>{
    const username=String(u.username||u.user||'')
    const display=String(u.display_name||'')
    const department=String(u.department||'')
    const role=String(u.role||'')
    const enabled=Boolean(u.monitoring_enabled??u.enabled??u.is_enabled)

    const searchOk=!searchWord||[
      username,display,department,role
    ].some(v=>v.toLowerCase().includes(searchWord))

    const departmentOk=
      departmentFilter==='ALL'||department===departmentFilter
    const roleOk=
      roleFilter==='ALL'||role===roleFilter
    const statusOk=
      statusFilter==='ALL'||
      (statusFilter==='ACTIVE'&&enabled)||
      (statusFilter==='INACTIVE'&&!enabled)

    return searchOk&&departmentOk&&roleOk&&statusOk
  })

  const USERS_PER_PAGE=10
  const totalUserPages=Math.max(
    1,
    Math.ceil(filteredUsers.length/USERS_PER_PAGE)
  )
  const safeUserPage=Math.min(userPage,totalUserPages)
  const pagedUsers=filteredUsers.slice(
    (safeUserPage-1)*USERS_PER_PAGE,
    safeUserPage*USERS_PER_PAGE
  )

  useEffect(()=>{
    setUserPage(1)
  },[
    userSearch,
    departmentFilter,
    roleFilter,
    statusFilter
  ])
'''
    app = app[:pos] + logic + app[pos:]
    print("[PATCH] 필터/페이지 계산 추가")

old_department = '<Field label="부서"><input placeholder="예: IT" value={form.department} onChange={e=>setForm({...form,department:e.target.value})}/></Field>'
new_department = '<Field label="부서"><select value={form.department} onChange={e=>setForm({...form,department:e.target.value})}><option value="">부서 선택</option>{departmentPresets.map(x=><option key={x} value={x}>{x}</option>)}</select></Field>'
if old_department in app:
    app = app.replace(old_department, new_department, 1)
    print("[PATCH] 부서 입력 -> 선택형")

old_role = '<Field label="역할"><input placeholder="예: Developer" value={form.role} onChange={e=>setForm({...form,role:e.target.value})}/></Field>'
new_role = '<Field label="직군"><select value={form.role} onChange={e=>setForm({...form,role:e.target.value})}><option value="">직군 선택</option>{rolePresets.map(x=><option key={x} value={x}>{x}</option>)}</select></Field>'
if old_role in app:
    app = app.replace(old_role, new_role, 1)
    print("[PATCH] 역할 입력 -> 직군 선택형")

caption = '<div className="section-caption">비활성화하면 새 /events 수집을 차단합니다. 삭제해도 기존 SecurityEvent 감사 이력은 보존됩니다.</div>'
if "user-filter-panel" not in app[start:]:
    idx = app.find(caption, start)
    if idx < 0:
        raise RuntimeError("사용자 관리 caption을 찾지 못했습니다.")
    idx += len(caption)
    toolbar = r'''
    <div className="user-filter-panel">
      <div className="user-filter-search">
        <span>사용자 검색</span>
        <input
          value={userSearch}
          onChange={e=>setUserSearch(e.target.value)}
          placeholder="이름 · 계정 · 부서 · 직군 검색"
        />
      </div>

      <label>
        <span>부서</span>
        <select
          value={departmentFilter}
          onChange={e=>setDepartmentFilter(e.target.value)}
        >
          <option value="ALL">전체 부서</option>
          {departments.map(x=>
            <option key={x} value={x}>{x}</option>
          )}
        </select>
      </label>

      <label>
        <span>직군</span>
        <select
          value={roleFilter}
          onChange={e=>setRoleFilter(e.target.value)}
        >
          <option value="ALL">전체 직군</option>
          {roles.map(x=>
            <option key={x} value={x}>{x}</option>
          )}
        </select>
      </label>

      <label>
        <span>모니터링</span>
        <select
          value={statusFilter}
          onChange={e=>setStatusFilter(e.target.value)}
        >
          <option value="ALL">전체 상태</option>
          <option value="ACTIVE">활성</option>
          <option value="INACTIVE">비활성</option>
        </select>
      </label>

      <div className="user-filter-summary">
        <span>검색 결과</span>
        <strong>{filteredUsers.length.toLocaleString()}명</strong>
        <small>전체 {users.length.toLocaleString()}명</small>
      </div>
    </div>
'''
    app = app[:idx] + toolbar + app[idx:]
    print("[PATCH] 검색/필터 toolbar 추가")

old = '{!tableMode?<div className="monitored-user-list">{users.map((u,i)=>'
new = '{!tableMode?<div className="monitored-user-list">{pagedUsers.map((u,i)=>'
if old in app:
    app = app.replace(old, new, 1)

old = "rows={users.map(u=>{const name=u.username||u.user||'-'"
new = "rows={pagedUsers.map(u=>{const name=u.username||u.user||'-'"
if old in app:
    app = app.replace(old, new, 1)

app = app.replace(
    "['사용자','표시 이름','부서','역할','모니터링','학습 상태','관리']",
    "['사용자','표시 이름','부서','직군','모니터링','학습 상태','관리']",
    1
)

adaptive_anchor = "    <SectionHeader>Adaptive Personal UEBA</SectionHeader>"
if 'className="user-pagination"' not in app[start:]:
    idx = app.find(adaptive_anchor, start)
    if idx < 0:
        raise RuntimeError("Adaptive Personal UEBA anchor를 찾지 못했습니다.")
    pagination = r'''    <div className="user-pagination">
      <button
        className="mini-btn"
        disabled={safeUserPage<=1}
        onClick={()=>setUserPage(p=>Math.max(1,p-1))}
      >
        이전
      </button>

      <span>
        {safeUserPage} / {totalUserPages} 페이지
        {' · '}
        {filteredUsers.length.toLocaleString()}명
      </span>

      <button
        className="mini-btn"
        disabled={safeUserPage>=totalUserPages}
        onClick={()=>setUserPage(p=>Math.min(totalUserPages,p+1))}
      >
        다음
      </button>
    </div>

'''
    app = app[:idx] + pagination + app[idx:]
    print("[PATCH] 10명 단위 페이지네이션 추가")

APP.write_text(app, encoding="utf-8")
print("[WRITE] sentinel-react-frontend/src/App.jsx")

css = CSS.read_text(encoding="utf-8")
marker = "/* ===== USER MANAGEMENT FILTER V6 ===== */"
if marker not in css:
    css_patch = r'''

/* ===== USER MANAGEMENT FILTER V6 ===== */
.register-grid select,
.user-filter-panel select,
.user-filter-panel input{
  width:100%;
  min-width:0;
  box-sizing:border-box;
  min-height:38px;
  padding:0 11px;
  border:1px solid #263345;
  border-radius:8px;
  outline:none;
  background:#1b222d;
  color:#dce3eb;
  font:inherit;
  font-size:11px;
}

.user-filter-panel{
  display:grid;
  grid-template-columns:minmax(220px,1.7fr) repeat(3,minmax(145px,1fr)) minmax(100px,.65fr);
  gap:10px;
  align-items:end;
  margin:14px 0 10px;
  padding:14px;
  border:1px solid #202b39;
  border-radius:10px;
  background:#0e141d;
}

.user-filter-panel label,
.user-filter-search{
  min-width:0;
}

.user-filter-panel label>span,
.user-filter-search>span{
  display:block;
  margin:0 0 6px 2px;
  color:#7d8a9a;
  font-size:9px;
  font-weight:650;
}

.user-filter-summary{
  display:flex;
  min-width:0;
  min-height:38px;
  flex-direction:column;
  justify-content:center;
  padding:0 10px;
  border-left:1px solid #263345;
}

.user-filter-summary span,
.user-filter-summary small{
  color:#687689;
  font-size:8px;
}

.user-filter-summary strong{
  margin:2px 0;
  color:#f0f4f8;
  font-size:17px;
  line-height:1;
}

.monitored-user-row,
.user-admin-card{
  min-width:0;
}

.user-admin-card{
  overflow:hidden;
}

.baseline-meta{
  max-width:100%;
  white-space:normal;
  word-break:keep-all;
  overflow-wrap:anywhere;
}

.user-pagination{
  display:flex;
  align-items:center;
  justify-content:center;
  gap:12px;
  margin:14px 0 22px;
}

.user-pagination span{
  min-width:170px;
  color:#8995a5;
  font-size:10px;
  text-align:center;
}

.user-pagination .mini-btn:disabled{
  opacity:.35;
  cursor:not-allowed;
}

@media(max-width:1250px){
  .user-filter-panel{
    grid-template-columns:repeat(2,minmax(0,1fr));
  }
  .user-filter-summary{
    border-left:0;
    border-top:1px solid #263345;
    padding-top:8px;
  }
}

@media(max-width:700px){
  .user-filter-panel{
    grid-template-columns:1fr;
  }
}
'''
    CSS.write_text(css + css_patch, encoding="utf-8")
    print("[PATCH] 사용자 필터 CSS 추가")

print()
print("=" * 80)
print("SENTINEL User Management v6 완료")
print("=" * 80)
print("- 부서/직군 선택형 등록")
print("- 사용자 검색")
print("- 부서/직군/활성상태 필터")
print("- 카드/표 보기 모두 필터 적용")
print("- 10명 단위 페이지네이션")
