/**
 * Derive the display language from a finding's file path.
 * Falls back to the finding's language field if no extension match.
 */
const EXTENSION_MAP: Record<string, string> = {
  '.py': 'python',
  '.js': 'javascript',
  '.mjs': 'javascript',
  '.cjs': 'javascript',
  '.jsx': 'javascript',
  '.ts': 'typescript',
  '.tsx': 'typescript',
  '.java': 'java',
  '.kt': 'kotlin',
  '.kts': 'kotlin',
  '.go': 'go',
  '.rs': 'rust',
  '.rb': 'ruby',
  '.php': 'php',
  '.c': 'c',
  '.h': 'c',
  '.cpp': 'cpp',
  '.cc': 'cpp',
  '.cxx': 'cpp',
  '.hpp': 'cpp',
  '.cs': 'csharp',
  '.swift': 'swift',
  '.m': 'objectivec',
  '.scala': 'scala',
  '.sh': 'shell',
  '.bash': 'shell',
  '.yaml': 'yaml',
  '.yml': 'yaml',
  '.xml': 'xml',
  '.html': 'html',
  '.properties': 'properties',
  '.ini': 'properties',
  '.cfg': 'properties',
  '.conf': 'properties',
  '.env': 'properties',
  '.toml': 'toml',
  '.json': 'json',
  '.sql': 'sql',
  '.dart': 'dart',
  '.r': 'r',
  '.lua': 'lua',
  '.pl': 'perl',
};

export function getFileLanguage(filePath: string, fallback: string): string {
  const lastDot = filePath.lastIndexOf('.');
  if (lastDot === -1) return fallback === 'universal' ? 'other' : fallback;

  const ext = filePath.slice(lastDot).toLowerCase();
  const detected = EXTENSION_MAP[ext];
  if (detected) return detected;

  // If the rule language isn't "universal", trust it
  if (fallback !== 'universal') return fallback;

  return 'other';
}
