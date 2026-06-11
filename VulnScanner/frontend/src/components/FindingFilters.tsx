import { useState, useMemo, useEffect } from 'react';
import { Filter, X, ChevronDown, ChevronUp } from 'lucide-react';
import { useScanStore } from '../store/scanStore';
import type { Finding, Severity } from '../api/types';
import { severityBgColors } from '../utils/severity';
import { getFileLanguage } from '../utils/languageDetect';

interface FilterState {
  severity: Set<Severity>;
  category: Set<string>;
  language: Set<string>;
  confidence: Set<string>;
  searchText: string;
}

const SEVERITIES: Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
const CONFIDENCES = ['HIGH', 'MEDIUM', 'LOW'];

interface Props {
  onFilteredFindings: (findings: Finding[]) => void;
  onSearchTextChange?: (text: string) => void;
}

export function FindingFilters({ onFilteredFindings, onSearchTextChange }: Props) {
  const { result } = useScanStore();
  const [expanded, setExpanded] = useState(false);
  const [filters, setFilters] = useState<FilterState>({
    severity: new Set(),
    category: new Set(),
    language: new Set(),
    confidence: new Set(),
    searchText: '',
  });

  // Extract unique values from findings
  const categories = useMemo(() => {
    if (!result?.findings) return [];
    return [...new Set(result.findings.map((f) => f.category))].sort();
  }, [result?.findings]);

  const languages = useMemo(() => {
    if (!result?.findings) return [];
    return [...new Set(result.findings.map((f) => getFileLanguage(f.file_path, f.language)))].sort();
  }, [result?.findings]);

  // Apply filters
  const filteredFindings = useMemo(() => {
    if (!result?.findings) return [];
    let findings = result.findings;

    if (filters.severity.size > 0) {
      findings = findings.filter((f) => filters.severity.has(f.severity));
    }
    if (filters.category.size > 0) {
      findings = findings.filter((f) => filters.category.has(f.category));
    }
    if (filters.language.size > 0) {
      findings = findings.filter((f) => filters.language.has(getFileLanguage(f.file_path, f.language)));
    }
    if (filters.confidence.size > 0) {
      findings = findings.filter((f) => filters.confidence.has(f.confidence));
    }
    if (filters.searchText.trim()) {
      const search = filters.searchText.toLowerCase();
      findings = findings.filter(
        (f) =>
          f.title.toLowerCase().includes(search) ||
          f.file_path.toLowerCase().includes(search) ||
          f.description.toLowerCase().includes(search) ||
          f.rule_id.toLowerCase().includes(search) ||
          f.cwe_id.toLowerCase().includes(search)
      );
    }

    return findings;
  }, [result?.findings, filters]);

  useEffect(() => {
    onFilteredFindings(filteredFindings);
  }, [filteredFindings, onFilteredFindings]);

  const activeFilterCount =
    filters.severity.size +
    filters.category.size +
    filters.language.size +
    filters.confidence.size +
    (filters.searchText ? 1 : 0);

  const toggleSet = <T extends string>(
    set: Set<T>,
    key: keyof FilterState,
    value: T
  ) => {
    const newSet = new Set(set);
    if (newSet.has(value)) {
      newSet.delete(value);
    } else {
      newSet.add(value);
    }
    setFilters((prev) => ({ ...prev, [key]: newSet }));
  };

  const clearFilters = () => {
    setFilters({
      severity: new Set(),
      category: new Set(),
      language: new Set(),
      confidence: new Set(),
      searchText: '',
    });
  };

  return (
    <div className="bg-slate-800 rounded-xl border border-slate-700 overflow-hidden">
      {/* Header */}
      <button
        onClick={() => setExpanded(!expanded)}
        className="w-full px-4 py-3 flex items-center justify-between hover:bg-slate-750 transition-colors"
      >
        <div className="flex items-center gap-2">
          <Filter className="w-4 h-4 text-slate-400" />
          <span className="text-sm font-medium text-slate-200">Filters</span>
          {activeFilterCount > 0 && (
            <span className="px-2 py-0.5 rounded-full bg-blue-600 text-xs text-white">
              {activeFilterCount}
            </span>
          )}
          {filteredFindings.length !== (result?.findings?.length || 0) && (
            <span className="text-xs text-slate-400">
              Showing {filteredFindings.length} of {result?.findings?.length}
            </span>
          )}
        </div>
        {expanded ? (
          <ChevronUp className="w-4 h-4 text-slate-400" />
        ) : (
          <ChevronDown className="w-4 h-4 text-slate-400" />
        )}
      </button>

      {/* Filter Panel */}
      {expanded && (
        <div className="px-4 pb-4 space-y-4 border-t border-slate-700 pt-3">
          {/* Search */}
          <div>
            <input
              type="text"
              value={filters.searchText}
              onChange={(e) => {
                setFilters((prev) => ({ ...prev, searchText: e.target.value }));
                onSearchTextChange?.(e.target.value);
              }}
              placeholder="Search findings (file, title, CWE, rule ID)..."
              className="w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded-lg text-sm text-slate-200 placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-blue-500"
            />
          </div>

          {/* Severity */}
          <div>
            <label className="text-xs font-medium text-slate-400 uppercase tracking-wide">
              Severity
            </label>
            <div className="flex flex-wrap gap-2 mt-1">
              {SEVERITIES.map((sev) => (
                <button
                  key={sev}
                  onClick={() => toggleSet(filters.severity, 'severity', sev)}
                  className={`px-2.5 py-1 rounded text-xs font-medium transition-all ${
                    filters.severity.has(sev)
                      ? `${severityBgColors[sev]} text-white ring-2 ring-white/30`
                      : 'bg-slate-700 text-slate-300 hover:bg-slate-600'
                  }`}
                >
                  {sev}
                  {result?.findings_by_severity?.[sev]
                    ? ` (${result.findings_by_severity[sev]})`
                    : ''}
                </button>
              ))}
            </div>
          </div>

          {/* Category */}
          <div>
            <label className="text-xs font-medium text-slate-400 uppercase tracking-wide">
              Category
            </label>
            <div className="flex flex-wrap gap-2 mt-1">
              {categories.map((cat) => (
                <button
                  key={cat}
                  onClick={() => toggleSet(filters.category, 'category', cat)}
                  className={`px-2.5 py-1 rounded text-xs font-medium transition-all ${
                    filters.category.has(cat)
                      ? 'bg-blue-600 text-white ring-2 ring-blue-400/30'
                      : 'bg-slate-700 text-slate-300 hover:bg-slate-600'
                  }`}
                >
                  {cat.replace(/_/g, ' ')}
                </button>
              ))}
            </div>
          </div>

          {/* Language */}
          <div>
            <label className="text-xs font-medium text-slate-400 uppercase tracking-wide">
              Language
            </label>
            <div className="flex flex-wrap gap-2 mt-1">
              {languages.map((lang) => (
                <button
                  key={lang}
                  onClick={() => toggleSet(filters.language, 'language', lang)}
                  className={`px-2.5 py-1 rounded text-xs font-medium transition-all ${
                    filters.language.has(lang)
                      ? 'bg-emerald-600 text-white ring-2 ring-emerald-400/30'
                      : 'bg-slate-700 text-slate-300 hover:bg-slate-600'
                  }`}
                >
                  {lang}
                </button>
              ))}
            </div>
          </div>

          {/* Confidence */}
          <div>
            <label className="text-xs font-medium text-slate-400 uppercase tracking-wide">
              Confidence
            </label>
            <div className="flex flex-wrap gap-2 mt-1">
              {CONFIDENCES.map((conf) => (
                <button
                  key={conf}
                  onClick={() => toggleSet(filters.confidence, 'confidence', conf)}
                  className={`px-2.5 py-1 rounded text-xs font-medium transition-all ${
                    filters.confidence.has(conf)
                      ? 'bg-purple-600 text-white ring-2 ring-purple-400/30'
                      : 'bg-slate-700 text-slate-300 hover:bg-slate-600'
                  }`}
                >
                  {conf}
                </button>
              ))}
            </div>
          </div>

          {/* Clear button */}
          {activeFilterCount > 0 && (
            <button
              onClick={clearFilters}
              className="flex items-center gap-1 px-3 py-1.5 rounded bg-red-900/30 border border-red-700 text-red-300 text-xs hover:bg-red-900/50 transition-colors"
            >
              <X className="w-3 h-3" />
              Clear all filters
            </button>
          )}
        </div>
      )}
    </div>
  );
}
