import { useEffect, useMemo, useState } from 'react';

const TABS = [
  { id: 'e2e', label: 'End-to-End', kicker: 'scan -> analyze -> validate' },
  { id: 'analysis', label: 'Analysis', kicker: 'patch or sanitizer code' },
  { id: 'validation', label: 'Validation', kicker: 'report replay' },
];

const API_BASE = import.meta.env.VITE_API_BASE_URL || '';
const POLL_INTERVAL_MS = 2000;
const TASK_LIST_LIMIT = 10;
const ACTIVE_TASK_STORAGE_KEY = 'sangraph.activeTaskId';

const initialE2E = { repo_path: '', scan_save_path: '' };
const initialAnalysis = { patch_path: '', sanitizer_code: '', repo_path: '' };
const initialValidation = { report_path: '', repo_path: '' };

function buildUrl(path) {
  return `${API_BASE}${path}`;
}

async function readResponsePayload(response) {
  const text = await response.text();
  if (!text) return {};
  try {
    return JSON.parse(text);
  } catch {
    return { message: text };
  }
}

async function requestJson(path, options = {}) {
  const response = await fetch(buildUrl(path), {
    headers: { 'Content-Type': 'application/json', ...(options.headers || {}) },
    ...options,
  });
  const payload = await readResponsePayload(response);
  if (!response.ok) {
    const message = payload.detail || payload.message || response.statusText;
    throw new Error(message);
  }
  return payload;
}

function bundleFileName(taskId, headerValue) {
  if (!headerValue) return `sangraph-task-${taskId}.zip`;
  const utf8Match = headerValue.match(/filename\*=UTF-8''([^;]+)/i);
  if (utf8Match?.[1]) return decodeURIComponent(utf8Match[1]);
  const asciiMatch = headerValue.match(/filename="?([^";]+)"?/i);
  if (asciiMatch?.[1]) return asciiMatch[1];
  return `sangraph-task-${taskId}.zip`;
}

async function requestBundle(taskId) {
  const response = await fetch(buildUrl(`/api/tasks/${taskId}/log-bundle`));
  if (!response.ok) {
    const payload = await readResponsePayload(response);
    const message = payload.detail || payload.message || response.statusText;
    throw new Error(message);
  }
  return {
    blob: await response.blob(),
    fileName: bundleFileName(taskId, response.headers.get('content-disposition')),
  };
}

function formatBool(value) {
  return value ? 'Yes' : 'No';
}

function badgeTone(status) {
  if (status === 'succeeded') return 'good';
  if (status === 'failed') return 'bad';
  if (status === 'running') return 'live';
  return 'idle';
}

function lineLabel(start, end) {
  if (start && end) return `${start}-${end}`;
  if (start) return `${start}`;
  return 'n/a';
}

function formatValidationSkipMessage(skipReason) {
  if (skipReason === 'repo_path_not_provided') {
    return 'Validation skipped because no repo_path was provided.';
  }
  if (skipReason === 'analysis_negative') {
    return 'Validation skipped because the analysis result looks safe.';
  }
  return 'Validation skipped.';
}

function formatValidationSkipBadge(skipReason) {
  if (skipReason === 'analysis_negative') {
    return 'validation skipped (analysis negative)';
  }
  if (skipReason === 'repo_path_not_provided') {
    return 'validation skipped (missing repo_path)';
  }
  return 'validation skipped';
}

function formatAnalysisProfile(profile) {
  if (profile === 'enhanced_search') return 'enhanced search';
  return 'standard';
}

function formatRagRelevanceLabel(relevance) {
  return relevance?.label || 'n/a';
}

function candidateStatusLabel(candidate) {
  if (candidate.status === 'failed') return 'failed';
  if (candidate.validation_skipped && candidate.skip_reason === 'analysis_negative') {
    return 'analysis safe / validation skipped';
  }
  if (candidate.validation_skipped && candidate.skip_reason === 'repo_path_not_provided') {
    return 'analysis only / missing repo_path';
  }
  return candidate.status;
}

function candidateStatusTone(candidate) {
  if (candidate.status === 'failed') return 'bad';
  if (candidate.validation_skipped && candidate.skip_reason === 'analysis_negative') return 'good';
  if (candidate.validation_skipped) return 'warn';
  return badgeTone(candidate.status);
}

function readStoredActiveTaskId() {
  if (typeof window === 'undefined') return '';
  try {
    return window.localStorage.getItem(ACTIVE_TASK_STORAGE_KEY) || '';
  } catch {
    return '';
  }
}

function writeStoredActiveTaskId(taskId) {
  if (typeof window === 'undefined') return;
  try {
    if (taskId) {
      window.localStorage.setItem(ACTIVE_TASK_STORAGE_KEY, taskId);
    } else {
      window.localStorage.removeItem(ACTIVE_TASK_STORAGE_KEY);
    }
  } catch {
    // Ignore storage failures so UI can still function.
  }
}

function sortTasks(tasks) {
  return [...tasks].sort((left, right) => {
    const leftActive = left.status === 'running' || left.status === 'queued';
    const rightActive = right.status === 'running' || right.status === 'queued';
    if (leftActive !== rightActive) return leftActive ? -1 : 1;
    return (right.created_at || '').localeCompare(left.created_at || '');
  });
}

function mergeTaskIntoList(tasks, task) {
  if (!task) return sortTasks(tasks);
  const next = tasks.filter((item) => item.task_id !== task.task_id);
  next.unshift(task);
  return sortTasks(next).slice(0, TASK_LIST_LIMIT);
}

async function fetchTaskList() {
  const payload = await requestJson(`/api/tasks?limit=${TASK_LIST_LIMIT}`);
  return sortTasks(payload.tasks || []);
}

async function fetchTaskDetail(taskId) {
  const statusPayload = await requestJson(`/api/tasks/${taskId}`);
  if (statusPayload.status === 'succeeded' || statusPayload.status === 'failed') {
    const resultPayload = await requestJson(`/api/tasks/${taskId}/result`);
    return resultPayload;
  }
  return statusPayload;
}

function StatusPill({ children, tone = 'idle' }) {
  return <span className={`pill pill-${tone}`}>{children}</span>;
}

function HealthStrip({ health }) {
  const entries = health?.checks ? Object.entries(health.checks) : [];
  return (
    <section className="health-strip panel">
      <div>
        <p className="eyebrow">Service</p>
        <h2>API health</h2>
        <p className="muted">
          Artifact root: <code>{health?.artifact_root || 'unknown'}</code>
        </p>
      </div>
      <div className="health-grid">
        {entries.map(([name, check]) => (
          <article key={name} className="health-card">
            <div className="health-card-head">
              <strong>{name}</strong>
              <StatusPill tone={check.available ? 'good' : 'bad'}>
                {check.available ? 'ready' : 'missing'}
              </StatusPill>
            </div>
            <p>{check.detail}</p>
          </article>
        ))}
      </div>
    </section>
  );
}

function TaskSummary({ task, onDownloadBundle, downloadingBundle }) {
  if (!task) return null;
  const finished = task.status === 'succeeded' || task.status === 'failed';
  return (
    <section className="panel task-panel">
      <div className="task-head">
        <div>
          <p className="eyebrow">Current task</p>
          <h2>{task.task_type}</h2>
          <p className="muted mono">{task.task_id}</p>
        </div>
        <div className="task-meta">
          <StatusPill tone={badgeTone(task.status)}>{task.status}</StatusPill>
          <span className="stage-chip">stage: {task.progress_stage}</span>
          {finished ? (
            <button
              className="secondary-button task-action-button"
              type="button"
              onClick={() => onDownloadBundle(task.task_id)}
              disabled={downloadingBundle}
            >
              {downloadingBundle ? 'Submitting...' : 'Download logs'}
            </button>
          ) : null}
        </div>
      </div>
      <div className="task-grid">
        <div>
          <p className="mini-label">Created</p>
          <code>{task.created_at}</code>
        </div>
        <div>
          <p className="mini-label">Finished</p>
          <code>{task.finished_at || 'running...'}</code>
        </div>
      </div>
      {task.error ? (
        <div className="callout callout-bad">
          <strong>{task.error.code}</strong>
          <p>{task.error.message}</p>
        </div>
      ) : null}
    </section>
  );
}

function RecentTasksPanel({ tasks, activeTaskId, loading, onSelect }) {
  return (
    <section className="panel recent-panel">
      <div className="recent-head">
        <div>
          <p className="eyebrow">Recent tasks</p>
          <h2>Running first</h2>
        </div>
        <p className="muted">Showing up to {TASK_LIST_LIMIT} tasks restored from server snapshots.</p>
      </div>
      {loading ? <p className="muted">Loading tasks...</p> : null}
      {!loading && tasks.length === 0 ? (
        <div className="callout">
          <p className="mini-label">No tasks</p>
          <p>No server-side task snapshots were found yet.</p>
        </div>
      ) : null}
      <div className="recent-list">
        {tasks.map((item) => {
          const isActive = item.task_id === activeTaskId;
          return (
            <button
              key={item.task_id}
              type="button"
              className={`recent-item ${isActive ? 'is-active' : ''}`}
              onClick={() => onSelect(item.task_id)}
            >
              <div className="recent-item-head">
                <strong>{item.task_type}</strong>
                <StatusPill tone={badgeTone(item.status)}>{item.status}</StatusPill>
              </div>
              <p className="muted mono recent-id">{item.task_id}</p>
              <div className="stack-inline wrap">
                <span className="stage-chip">stage: {item.progress_stage}</span>
                <span className="recent-meta-label">created: {item.created_at}</span>
              </div>
            </button>
          );
        })}
      </div>
    </section>
  );
}

function AnalysisResultView({ result }) {
  const analysis = result.analysis_result;
  const validation = result.validation_result;
  const ragRelevance = analysis?.rag_relevance;
  return (
    <section className="panel results-panel">
      <div className="results-head">
        <div>
          <p className="eyebrow">Analysis result</p>
          <h2>{analysis?.is_vuln ? 'Potentially vulnerable' : 'Looks safer'}</h2>
        </div>
        <div className="stack-inline">
          <StatusPill tone={analysis?.is_vuln ? 'bad' : 'good'}>
            vuln: {formatBool(analysis?.is_vuln)}
          </StatusPill>
          <StatusPill tone="live">confidence: {analysis?.confidence || 'n/a'}</StatusPill>
        </div>
      </div>
      <div className="metric-grid">
        <article>
          <p className="mini-label">Validation attempted</p>
          <strong>{formatBool(result.validation_attempted)}</strong>
        </article>
        <article>
          <p className="mini-label">Validation skipped</p>
          <strong>{formatBool(result.validation_skipped)}</strong>
        </article>
        <article>
          <p className="mini-label">Verdict source</p>
          <strong>{analysis?.final_verdict_source || 'n/a'}</strong>
        </article>
        <article>
          <p className="mini-label">Analysis profile</p>
          <strong>{formatAnalysisProfile(analysis?.analysis_profile)}</strong>
        </article>
        <article>
          <p className="mini-label">Analysis backend</p>
          <strong>{analysis?.analysis_backend || 'n/a'}</strong>
        </article>
        <article>
          <p className="mini-label">RAG relevance</p>
          <strong>{formatRagRelevanceLabel(ragRelevance)}</strong>
        </article>
      </div>
      <div className="callout">
        <p className="mini-label">Reasoning</p>
        <p>{analysis?.reasoning || 'No reasoning returned.'}</p>
      </div>
      <div className="callout">
        <p className="mini-label">Evidence summary</p>
        <p>{analysis?.evidence_summary || 'No extra evidence summary returned.'}</p>
      </div>
      <div className={`callout ${analysis?.external_evidence_used ? '' : 'callout-warn'}`}>
        <p className="mini-label">Public evidence</p>
        <p>{analysis?.external_evidence_reason || 'No public evidence note returned.'}</p>
        {analysis?.external_evidence_sources?.length ? (
          <pre>{JSON.stringify(analysis.external_evidence_sources, null, 2)}</pre>
        ) : (
          <p className="muted">No public evidence sources recorded.</p>
        )}
      </div>
      {ragRelevance?.reason ? (
        <div className="callout">
          <p className="mini-label">RAG relevance note</p>
          <p>{ragRelevance.reason}</p>
        </div>
      ) : null}
      {result.validation_skipped ? (
        <div className="callout callout-warn">
          <p className="mini-label">Validation</p>
          <p>{formatValidationSkipMessage(result.skip_reason)}</p>
          <p className="muted">
            reason code: <code>{result.skip_reason}</code>
          </p>
        </div>
      ) : validation ? (
        <div className="validation-panel">
          <div className="results-head compact">
            <h3>Validation verdict</h3>
            <StatusPill tone={validation.verdict === 'confirmed' ? 'bad' : validation.verdict === 'not_reproduced' ? 'good' : 'live'}>
              {validation.verdict}
            </StatusPill>
          </div>
          <div className="metric-grid">
            <article>
              <p className="mini-label">Strategy</p>
              <strong>{validation.strategy}</strong>
            </article>
            <article>
              <p className="mini-label">Executed command</p>
              <code>{validation.executed_command}</code>
            </article>
          </div>
          <div className="callout">
            <p className="mini-label">Reasoning</p>
            <p>{validation.reasoning}</p>
          </div>
        </div>
      ) : null}
      <details>
        <summary>Artifacts</summary>
        <pre>{JSON.stringify(result.artifacts, null, 2)}</pre>
      </details>
    </section>
  );
}

function ValidationResultView({ result }) {
  const validation = result.validation_result;
  return (
    <section className="panel results-panel">
      <div className="results-head">
        <div>
          <p className="eyebrow">Validation result</p>
          <h2>{validation?.verdict || 'No verdict'}</h2>
        </div>
        <StatusPill tone={validation?.verdict === 'confirmed' ? 'bad' : validation?.verdict === 'not_reproduced' ? 'good' : 'live'}>
          {validation?.strategy || 'strategy n/a'}
        </StatusPill>
      </div>
      <div className="callout">
        <p className="mini-label">Reasoning</p>
        <p>{validation?.reasoning || 'No reasoning returned.'}</p>
      </div>
      <details>
        <summary>Artifacts</summary>
        <pre>{JSON.stringify(result.artifacts, null, 2)}</pre>
      </details>
    </section>
  );
}

function CandidateRunCard({ candidate }) {
  const validation = candidate.validation_result;
  return (
    <article className="candidate-card">
      <div className="candidate-head">
        <div>
          <p className="mini-label">Candidate #{candidate.candidate_index}</p>
          <h3>{candidate.candidate_path || 'inline candidate'}</h3>
          <p className="muted">lines {lineLabel(candidate.start_line, candidate.end_line)}</p>
        </div>
        <StatusPill tone={candidateStatusTone(candidate)}>{candidateStatusLabel(candidate)}</StatusPill>
      </div>
      <div className="stack-inline wrap">
        {candidate.analysis_result ? (
          <StatusPill tone={candidate.analysis_result.is_vuln ? 'bad' : 'good'}>
            analysis vuln: {formatBool(candidate.analysis_result.is_vuln)}
          </StatusPill>
        ) : null}
        {validation ? (
          <StatusPill tone={validation.verdict === 'confirmed' ? 'bad' : validation.verdict === 'not_reproduced' ? 'good' : 'live'}>
            validation: {validation.verdict}
          </StatusPill>
        ) : null}
        {candidate.validation_skipped ? (
          <StatusPill tone={candidate.skip_reason === 'analysis_negative' ? 'good' : 'warn'}>
            {formatValidationSkipBadge(candidate.skip_reason)}
          </StatusPill>
        ) : null}
      </div>
      <div className="code-panel">
        <p className="mini-label">Candidate code</p>
        <pre>{candidate.candidate_code || 'No code payload.'}</pre>
      </div>
      {candidate.validation_skipped && !candidate.error ? (
        <div className="callout">
          <p className="mini-label">Validation</p>
          <p>{formatValidationSkipMessage(candidate.skip_reason)}</p>
        </div>
      ) : null}
      {candidate.error ? (
        <div className="callout callout-bad">
          <strong>{candidate.error.code}</strong>
          <p>{candidate.error.message}</p>
        </div>
      ) : null}
    </article>
  );
}

function E2EResultView({ result }) {
  const summary = result.summary || {};
  return (
    <section className="panel results-panel">
      <div className="results-head">
        <div>
          <p className="eyebrow">End-to-end run</p>
          <h2>{result.scan_candidate_count || 0} candidates</h2>
        </div>
        <div className="stack-inline">
          <StatusPill tone="good">ok: {summary.successful_candidates || 0}</StatusPill>
          <StatusPill tone={summary.failed_candidates ? 'bad' : 'good'}>
            failed: {summary.failed_candidates || 0}
          </StatusPill>
          {summary.partial_failures ? <StatusPill tone="warn">partial failures</StatusPill> : null}
        </div>
      </div>
      <div className="callout">
        <p className="mini-label">Scan output</p>
        <code>{result.scan_output_path}</code>
      </div>
      <div className="candidate-grid">
        {(result.candidate_runs || []).map((candidate) => (
          <CandidateRunCard key={`${candidate.candidate_index}-${candidate.candidate_path}`} candidate={candidate} />
        ))}
      </div>
    </section>
  );
}

function ResultsView({ task }) {
  if (!task?.result) return null;
  if (task.task_type === 'analysis') return <AnalysisResultView result={task.result} />;
  if (task.task_type === 'validation') return <ValidationResultView result={task.result} />;
  return <E2EResultView result={task.result} />;
}

function App() {
  const [activeTab, setActiveTab] = useState('e2e');
  const [analysisMode, setAnalysisMode] = useState('patch');
  const [analysisProfile, setAnalysisProfile] = useState('standard');
  const [e2eForm, setE2EForm] = useState(initialE2E);
  const [analysisForm, setAnalysisForm] = useState(initialAnalysis);
  const [validationForm, setValidationForm] = useState(initialValidation);
  const [health, setHealth] = useState(null);
  const [task, setTask] = useState(null);
  const [activeTaskId, setActiveTaskId] = useState(() => readStoredActiveTaskId());
  const [recentTasks, setRecentTasks] = useState([]);
  const [recentTasksLoading, setRecentTasksLoading] = useState(true);
  const [initialTaskResolved, setInitialTaskResolved] = useState(false);
  const [error, setError] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [downloadingBundle, setDownloadingBundle] = useState(false);

  const activeTask = task;

  useEffect(() => {
    requestJson('/api/health')
      .then(setHealth)
      .catch((err) => setError(`Health check failed: ${err.message}`));
  }, []);

  useEffect(() => {
    let cancelled = false;

    async function restoreTasks() {
      setRecentTasksLoading(true);
      try {
        const tasks = await fetchTaskList();
        if (cancelled) return;
        setRecentTasks(tasks);

        const runningTask = tasks.find((item) => item.status === 'running' || item.status === 'queued');
        const preferredTaskId = runningTask?.task_id || activeTaskId || tasks[0]?.task_id || '';

        if (!preferredTaskId) {
          setTask(null);
          setActiveTaskId('');
          writeStoredActiveTaskId('');
          return;
        }

        const detail = await fetchTaskDetail(preferredTaskId);
        if (cancelled) return;
        setTask(detail);
        setActiveTaskId(preferredTaskId);
        writeStoredActiveTaskId(preferredTaskId);
        setRecentTasks((current) => mergeTaskIntoList(current, detail));
      } catch (err) {
        if (cancelled) return;
        if (activeTaskId && /Unknown task/.test(err.message)) {
          setActiveTaskId('');
          writeStoredActiveTaskId('');
        } else {
          setError(err.message);
        }
      } finally {
        if (!cancelled) {
          setRecentTasksLoading(false);
          setInitialTaskResolved(true);
        }
      }
    }

    restoreTasks();

    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    if (!activeTaskId) {
      writeStoredActiveTaskId('');
      return;
    }
    writeStoredActiveTaskId(activeTaskId);
  }, [activeTaskId]);

  useEffect(() => {
    if (!activeTask || activeTask.task_id !== activeTaskId) return undefined;
    if (activeTask.status === 'succeeded' || activeTask.status === 'failed') return undefined;

    const timer = window.setInterval(async () => {
      try {
        const detail = await fetchTaskDetail(activeTaskId);
        setTask(detail);
        setRecentTasks((current) => mergeTaskIntoList(current, detail));
      } catch (err) {
        if (/Unknown task/.test(err.message)) {
          setTask(null);
          setActiveTaskId('');
          writeStoredActiveTaskId('');
        }
        setError(err.message);
      }
    }, POLL_INTERVAL_MS);

    return () => window.clearInterval(timer);
  }, [activeTask, activeTaskId]);

  const panelTitle = useMemo(() => TABS.find((tab) => tab.id === activeTab), [activeTab]);

  async function loadTask(taskId) {
    setError('');
    setActiveTaskId(taskId);
    try {
      const detail = await fetchTaskDetail(taskId);
      setTask(detail);
      setRecentTasks((current) => mergeTaskIntoList(current, detail));
    } catch (err) {
      if (/Unknown task/.test(err.message)) {
        setActiveTaskId('');
        writeStoredActiveTaskId('');
        setRecentTasks((current) => current.filter((item) => item.task_id !== taskId));
      }
      setError(err.message);
    }
  }

  async function refreshRecentTasks() {
    try {
      const tasks = await fetchTaskList();
      setRecentTasks(tasks);
    } catch (err) {
      setError(err.message);
    }
  }

  async function submitTask(path, payload) {
    setSubmitting(true);
    setError('');
    try {
      const created = await requestJson(path, { method: 'POST', body: JSON.stringify(payload) });
      await loadTask(created.task_id);
      await refreshRecentTasks();
    } catch (err) {
      setError(err.message);
    } finally {
      setSubmitting(false);
    }
  }

  async function handleDownloadBundle(taskId) {
    setDownloadingBundle(true);
    setError('');
    try {
      const { blob, fileName } = await requestBundle(taskId);
      const url = window.URL.createObjectURL(blob);
      const anchor = document.createElement('a');
      anchor.href = url;
      anchor.download = fileName;
      document.body.appendChild(anchor);
      anchor.click();
      anchor.remove();
      window.URL.revokeObjectURL(url);
    } catch (err) {
      setError(err.message);
    } finally {
      setDownloadingBundle(false);
    }
  }

  function handleE2ESubmit(event) {
    event.preventDefault();
    const payload = { repo_path: e2eForm.repo_path.trim() };
    if (e2eForm.scan_save_path.trim()) payload.scan_save_path = e2eForm.scan_save_path.trim();
    submitTask('/api/tasks/e2e', payload);
  }

  function handleAnalysisSubmit(event, profile = 'standard') {
    event.preventDefault();
    setAnalysisProfile(profile);
    const payload = {};
    if (analysisMode === 'patch') payload.patch_path = analysisForm.patch_path.trim();
    if (analysisMode === 'code') payload.sanitizer_code = analysisForm.sanitizer_code;
    if (analysisForm.repo_path.trim()) payload.repo_path = analysisForm.repo_path.trim();
    payload.analysis_profile = profile;
    submitTask('/api/tasks/analysis', payload);
  }

  function handleValidationSubmit(event) {
    event.preventDefault();
    submitTask('/api/tasks/validation', {
      report_path: validationForm.report_path.trim(),
      repo_path: validationForm.repo_path.trim(),
    });
  }

  return (
    <div className="shell">
      <header className="hero">
        <div className="hero-copy">
          <p className="eyebrow">SanGraph Web Workbench</p>
          <h1>Inspect defenses, then prove them.</h1>
          <p className="hero-text">
            Run scan-driven workflows, send a patch or sanitizer snippet through analysis, or validate an existing report.
          </p>
        </div>
        <div className="hero-panel">
          <p className="mini-label">Active lane</p>
          <h2>{panelTitle?.label}</h2>
          <p>{panelTitle?.kicker}</p>
        </div>
      </header>

      <HealthStrip health={health} />

      <div className="workspace">
        <section className="panel form-panel">
          <div className="tab-row" role="tablist" aria-label="Workflow tabs">
            {TABS.map((tab) => (
              <button
                key={tab.id}
                type="button"
                className={`tab-button ${activeTab === tab.id ? 'is-active' : ''}`}
                onClick={() => setActiveTab(tab.id)}
              >
                <span>{tab.label}</span>
                <small>{tab.kicker}</small>
              </button>
            ))}
          </div>

          {activeTab === 'e2e' ? (
            <form className="form-grid" onSubmit={handleE2ESubmit}>
              <label>
                <span>Repository path</span>
                <input
                  value={e2eForm.repo_path}
                  onChange={(event) => setE2EForm({ ...e2eForm, repo_path: event.target.value })}
                  placeholder="/path/to/checked-out/repo"
                  required
                />
              </label>
              <label>
                <span>Scan output path (optional)</span>
                <input
                  value={e2eForm.scan_save_path}
                  onChange={(event) => setE2EForm({ ...e2eForm, scan_save_path: event.target.value })}
                  placeholder="other/artifacts/web/custom_scan.json"
                />
              </label>
              <button className="primary-button" disabled={submitting} type="submit">
                {submitting ? 'Submitting...' : 'Run end-to-end'}
              </button>
            </form>
          ) : null}

          {activeTab === 'analysis' ? (
            <form className="form-grid" onSubmit={handleAnalysisSubmit}>
              <div className="mode-switch">
                <button
                  type="button"
                  className={analysisMode === 'patch' ? 'is-active' : ''}
                  onClick={() => setAnalysisMode('patch')}
                >
                  patch_path
                </button>
                <button
                  type="button"
                  className={analysisMode === 'code' ? 'is-active' : ''}
                  onClick={() => setAnalysisMode('code')}
                >
                  sanitizer_code
                </button>
              </div>
              {analysisMode === 'patch' ? (
                <label>
                  <span>Patch path</span>
                  <input
                    value={analysisForm.patch_path}
                    onChange={(event) => setAnalysisForm({ ...analysisForm, patch_path: event.target.value })}
                    placeholder="/path/to/fix.patch"
                    required
                  />
                </label>
              ) : (
                <label className="full-span">
                  <span>Sanitizer code</span>
                  <textarea
                    value={analysisForm.sanitizer_code}
                    onChange={(event) => setAnalysisForm({ ...analysisForm, sanitizer_code: event.target.value })}
                    placeholder="Paste sanitizer logic here"
                    required
                    rows={12}
                  />
                </label>
              )}
              <label>
                <span>Repository path (optional)</span>
                <input
                  value={analysisForm.repo_path}
                  onChange={(event) => setAnalysisForm({ ...analysisForm, repo_path: event.target.value })}
                  placeholder="Leave blank to skip validation"
                />
              </label>
              <p className="hint full-span">
                If <code>repo_path</code> is present, analysis automatically continues into validation. Leave it blank to run analysis only.
              </p>
              <div className="action-row full-span">
                <button className="primary-button" disabled={submitting} type="submit">
                  {submitting && analysisProfile === 'standard' ? 'Submitting...' : 'Run analysis'}
                </button>
                <button
                  className="secondary-button"
                  disabled={submitting}
                  type="button"
                  onClick={(event) => handleAnalysisSubmit(event, 'enhanced_search')}
                >
                  {submitting && analysisProfile === 'enhanced_search' ? 'Submitting...' : 'Enhanced analysis'}
                </button>
              </div>
            </form>
          ) : null}

          {activeTab === 'validation' ? (
            <form className="form-grid" onSubmit={handleValidationSubmit}>
              <label>
                <span>Report path</span>
                <input
                  value={validationForm.report_path}
                  onChange={(event) => setValidationForm({ ...validationForm, report_path: event.target.value })}
                  placeholder="/path/to/report.json"
                  required
                />
              </label>
              <label>
                <span>Repository path</span>
                <input
                  value={validationForm.repo_path}
                  onChange={(event) => setValidationForm({ ...validationForm, repo_path: event.target.value })}
                  placeholder="/path/to/checked-out/repo"
                  required
                />
              </label>
              <button className="primary-button" disabled={submitting} type="submit">
                {submitting ? 'Submitting...' : 'Run validation'}
              </button>
            </form>
          ) : null}
        </section>

        <div className="results-column">
          {error ? <div className="callout callout-bad standalone">{error}</div> : null}
          <RecentTasksPanel
            tasks={recentTasks}
            activeTaskId={activeTaskId}
            loading={recentTasksLoading && !initialTaskResolved}
            onSelect={loadTask}
          />
          <TaskSummary task={activeTask} onDownloadBundle={handleDownloadBundle} downloadingBundle={downloadingBundle} />
          <ResultsView task={activeTask} />
        </div>
      </div>
    </div>
  );
}

export default App;
