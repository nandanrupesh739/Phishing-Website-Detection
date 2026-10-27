import { useState, useEffect } from 'react';
import { Info, Shield, Code2, Database, GitBranch, AlertTriangle, Zap, ExternalLink } from 'lucide-react';
import { fetchModelInfo, fetchModelMetrics } from '../services/api';
import type { ModelInfoResponse, ModelMetricsResponse } from '../types/api';
import { formatNumber, formatPercent } from '../utils/formatters';

const TECH_STACK = [
  { category: 'Machine Learning', items: ['Python 3.11', 'Scikit-learn', 'Pandas', 'NumPy', 'Joblib'] },
  { category: 'Visualisation',    items: ['Matplotlib', 'Seaborn', 'Recharts (frontend)'] },
  { category: 'Backend',          items: ['Flask 3', 'Flask-CORS', 'SQLite', 'Python-dotenv'] },
  { category: 'Frontend',         items: ['React 18', 'Vite', 'TypeScript', 'Tailwind CSS 3', 'Lucide React'] },
  { category: 'Testing',          items: ['Pytest', 'pytest-cov', 'Vitest', 'Testing Library'] },
];

const LIMITATIONS = [
  'URL-structure features only — no DNS, WHOIS, page content, or screenshots',
  'Model cannot detect newly registered domains or zero-day phishing attacks',
  'HTTPS alone is not treated as evidence of legitimacy (correct, but novel to users)',
  'Punycode / IDN homograph attacks may evade URL-only detection',
  'Adversarially crafted URLs with clean structure may evade the model',
  'Model performance on URLs not in the training distribution may be lower',
  'Not a replacement for browser security warnings or professional threat intelligence',
];

const FUTURE = [
  'Optional DNS / WHOIS lookup via separate, configurable threat-intelligence service',
  'Integrate VirusTotal or Safe Browsing API (with explicit user consent and disclosure)',
  'SHAP-based local prediction explanations',
  'Periodic model retraining with fresh phishing feeds',
  'Browser extension with real-time URL checking',
  'User-supplied false-positive / false-negative feedback loop',
];

function Section({ title, icon, children }: { title: string; icon: React.ReactNode; children: React.ReactNode }) {
  return (
    <section className="glass-card p-6 space-y-4">
      <h2 className="section-title">
        {icon}
        {title}
      </h2>
      {children}
    </section>
  );
}

function BulletList({ items, color = '#60a5fa' }: { items: string[]; color?: string }) {
  return (
    <ul className="space-y-2">
      {items.map((item, i) => (
        <li key={i} className="flex items-start gap-2.5 text-sm text-slate-300">
          <span className="w-1.5 h-1.5 rounded-full mt-1.5 shrink-0" style={{ background: color }} />
          {item}
        </li>
      ))}
    </ul>
  );
}

export default function About() {
  const [info, setInfo] = useState<ModelInfoResponse | null>(null);
  const [metrics, setMetrics] = useState<ModelMetricsResponse | null>(null);

  useEffect(() => {
    Promise.all([
      fetchModelInfo().catch(() => null),
      fetchModelMetrics().catch(() => null),
    ]).then(([infoRes, metricsRes]) => {
      if (infoRes) setInfo(infoRes);
      if (metricsRes) setMetrics(metricsRes);
    });
  }, []);

  const featureCount = info?.feature_count ?? 42;
  const datasetSize = info?.dataset_size ? formatNumber(info.dataset_size) : '235,795';
  const targetRecallPct = info?.target_phishing_recall
    ? `${(info.target_phishing_recall * 100).toFixed(0)}%`
    : '98%';
  const splitText = info?.split_description ?? '70/15/15 Domain-Grouped split by registered domain (zero train/val/test domain leakage)';
  const accuracyStr = metrics?.test_metrics
    ? formatPercent(metrics.test_metrics.accuracy ?? metrics.test_metrics.test_accuracy)
    : '—';

  const dynamicFeatures = [
    `URL-string feature extraction (${featureCount} structural features + character n-gram TF-IDF, no network requests)`,
    'Multi-model evaluation: LightGBM, Logistic Regression, Random Forest, Naive Bayes',
    splitText,
    'Probability calibration via CalibratedClassifierCV with reliability curve and Brier score',
    `Decision threshold tuned on validation set to achieve target ${targetRecallPct} phishing recall`,
    `Single held-out test evaluation (${accuracyStr !== '—' ? `${accuracyStr} test accuracy` : 'honest reporting on unseen domains'})`,
    'Confusion matrix, ROC curve, reliability diagram, and feature importance reports',
    'Local SQLite scan history with pagination and clear functionality',
    'Responsive cybersecurity-themed dashboard with risk level indicators',
    'Full REST API with rate limiting, input validation, and safe error handling',
  ];

  const workflowSteps = [
    ['Load Dataset', `Detect URL and label columns; validate CSV structure (${datasetSize} samples) and compute fingerprint`],
    ['Clean & Normalise', 'Remove missing values and duplicates; apply canonical normalisation across training & inference'],
    ['Extract Features', `${featureCount} structural features via offline tldextract & regex + character n-gram TF-IDF (no network calls)`],
    ['Domain-Grouped Split', splitText],
    ['Train Candidates', 'Fit LightGBM, Logistic Regression, Random Forest, and Naive Bayes models with class weighting'],
    ['Validation Selection', 'Compare models on validation set; calibrate winning model with CalibratedClassifierCV'],
    ['Tune Threshold', `Select decision threshold on validation set to hit target ${targetRecallPct} recall and minimize false positives`],
    ['Held-Out Test', `Evaluate best calibrated model exactly once on test set (${accuracyStr} accuracy); generate reliability curve and confusion matrix`],
    ['Save Artefacts', 'Persist model bundle, metadata JSON, metrics contract, and visual report plots'],
  ];

  return (
    <div className="max-w-3xl mx-auto space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-white flex items-center gap-3">
          <div className="p-2 rounded-lg" style={{ background: 'linear-gradient(135deg,rgba(6,182,212,0.2),rgba(59,130,246,0.2))' }}>
            <Info size={22} className="text-teal-400" />
          </div>
          About PhishGuard AI
        </h1>
        <p className="text-slate-400 text-sm mt-1 ml-11">
          Educational machine learning project for phishing URL detection
        </p>
      </div>

      {/* Problem statement */}
      <Section title="Problem Statement" icon={<AlertTriangle size={18} className="text-amber-400" />}>
        <p className="text-slate-300 text-sm leading-relaxed">
          Phishing attacks remain one of the most prevalent cybersecurity threats, accounting for a significant
          fraction of all successful breaches. Attackers craft convincing fake websites that mimic legitimate
          services to steal credentials, financial information, and personal data.
        </p>
        <p className="text-slate-400 text-sm leading-relaxed mt-3">
          URL-based detection provides a first line of defence by analysing the structure of a URL before any
          network request is made — without loading the page, executing JavaScript, or exposing the user's
          browser to malicious content.
        </p>
      </Section>

      {/* Objectives */}
      <Section title="Project Objectives" icon={<Shield size={18} className="text-blue-400" />}>
        <BulletList items={[
          'Demonstrate end-to-end machine learning pipeline: data → features → model → API → UI',
          'Extract interpretable URL-string features without making network requests',
          'Compare multiple classifiers and select the best using a validation set',
          'Provide a transparent model evaluation with test-set metrics only',
          'Build a professional, accessible cybersecurity dashboard',
          'Prioritise phishing recall over precision to minimise false negatives',
          'Maintain cybersecurity best practices: no URL visits, no iframe rendering',
        ]} />
      </Section>

      {/* Features */}
      <Section title="Key Features" icon={<Zap size={18} className="text-violet-400" />}>
        <BulletList items={dynamicFeatures} color="#a78bfa" />
      </Section>

      {/* Tech stack */}
      <Section title="Technology Stack" icon={<Code2 size={18} className="text-teal-400" />}>
        <div className="grid sm:grid-cols-2 gap-4">
          {TECH_STACK.map(({ category, items }) => (
            <div key={category} className="space-y-2">
              <div className="text-xs font-semibold uppercase tracking-wider text-teal-400">{category}</div>
              <div className="flex flex-wrap gap-1.5">
                {items.map(item => (
                  <span key={item} className="text-xs px-2.5 py-1 rounded-md"
                    style={{ background: 'rgba(6,182,212,0.08)', color: '#94a3b8', border: '1px solid rgba(6,182,212,0.15)' }}>
                    {item}
                  </span>
                ))}
              </div>
            </div>
          ))}
        </div>
      </Section>

      {/* Dataset */}
      <Section title="Dataset" icon={<Database size={18} className="text-blue-400" />}>
        <div className="space-y-3 text-sm">
          <div className="p-4 rounded-xl space-y-2" style={{ background: 'rgba(59,130,246,0.06)', border: '1px solid rgba(59,130,246,0.15)' }}>
            <div className="text-white font-semibold">PhiUSIIL Phishing URL Dataset</div>
            <div className="text-slate-400">UCI Machine Learning Repository</div>
            <div className="flex flex-wrap gap-3 text-xs">
              {[
                ['Records', datasetSize],
                ['Features', formatNumber(featureCount)],
                ['Test Accuracy', accuracyStr],
                ['Target Recall', targetRecallPct],
              ].map(([k, v]) => (
                <div key={k} className="flex gap-1.5">
                  <span className="text-slate-500">{k}:</span>
                  <span className="text-slate-300 font-medium">{v}</span>
                </div>
              ))}
            </div>
          </div>
          <p className="text-slate-400">
            Citation: Prasad, A., &amp; Chandra, S. (2023). PhiUSIIL Phishing URL (Website) Dataset.
            UCI Machine Learning Repository.
            <a
              href="https://doi.org/10.24432/C59S6B"
              target="_blank"
              rel="noopener noreferrer"
              className="ml-1 text-blue-400 hover:text-blue-300 inline-flex items-center gap-1"
            >
              doi:10.24432/C59S6B <ExternalLink size={12} />
            </a>
          </p>
          <p className="text-slate-500 text-xs">
            Licensed under CC BY 4.0. Attribution required when using this dataset.
          </p>
        </div>
      </Section>

      {/* ML workflow */}
      <Section title="Machine Learning Workflow" icon={<GitBranch size={18} className="text-violet-400" />}>
        <ol className="space-y-3">
          {workflowSteps.map(([step, desc], i) => (
            <li key={step} className="flex items-start gap-3">
              <div className="w-6 h-6 rounded-full text-xs font-bold flex items-center justify-center shrink-0 mt-0.5"
                style={{ background: 'rgba(139,92,246,0.2)', color: '#a78bfa', border: '1px solid rgba(139,92,246,0.3)' }}>
                {i + 1}
              </div>
              <div>
                <div className="text-sm font-semibold text-white">{step}</div>
                <div className="text-sm text-slate-400 mt-0.5">{desc}</div>
              </div>
            </li>
          ))}
        </ol>
      </Section>

      {/* Limitations */}
      <Section title="Known Limitations" icon={<AlertTriangle size={18} className="text-amber-400" />}>
        <BulletList items={LIMITATIONS} color="#fbbf24" />
      </Section>

      {/* Future scope */}
      <Section title="Future Enhancements" icon={<Zap size={18} className="text-teal-400" />}>
        <BulletList items={FUTURE} color="#34d399" />
      </Section>

      {/* Disclaimer */}
      <div className="flex items-start gap-3 px-4 py-4 rounded-xl text-sm"
        style={{ background: 'rgba(239,68,68,0.05)', border: '1px solid rgba(239,68,68,0.2)' }}>
        <AlertTriangle size={16} className="shrink-0 mt-0.5 text-red-400" />
        <div className="text-slate-400 space-y-1">
          <div className="text-white font-semibold">Important Disclaimer</div>
          <p>
            PhishGuard AI is an <strong className="text-white">educational project</strong> demonstrating machine
            learning applied to cybersecurity. It is <em>not</em> a certified threat-intelligence product and must
            not be used as the sole basis for security decisions. Always rely on up-to-date browser security
            warnings, endpoint protection software, and professional threat-intelligence services for production
            security requirements.
          </p>
        </div>
      </div>
    </div>
  );
}
