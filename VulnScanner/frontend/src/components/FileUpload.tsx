import { useCallback, useState } from 'react';
import { Upload, FileArchive } from 'lucide-react';
import { useScan } from '../hooks/useScan';

export function FileUpload() {
  const { startScan } = useScan();
  const [dragOver, setDragOver] = useState(false);

  const handleFile = useCallback((file: File) => {
    if (!file.name.endsWith('.zip')) {
      alert('Please upload a .zip file');
      return;
    }
    if (file.size > 100 * 1024 * 1024) {
      alert('File size must be under 100MB');
      return;
    }
    startScan(file);
  }, [startScan]);

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setDragOver(false);
    const file = e.dataTransfer.files[0];
    if (file) handleFile(file);
  }, [handleFile]);

  const handleChange = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) handleFile(file);
  }, [handleFile]);

  return (
    <div
      onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
      onDragLeave={() => setDragOver(false)}
      onDrop={handleDrop}
      className={`relative rounded-xl p-8 text-center transition-all cursor-pointer h-full flex flex-col justify-center border-2 border-dashed ${
        dragOver
          ? 'border-indigo-400 bg-indigo-500/10 shadow-lg shadow-indigo-500/10'
          : 'border-slate-600 bg-slate-800/50 hover:border-indigo-500/50 hover:bg-slate-800/80'
      }`}
    >
      <input
        type="file"
        accept=".zip"
        onChange={handleChange}
        className="hidden"
        id="file-upload"
      />
      <label htmlFor="file-upload" className="cursor-pointer flex flex-col items-center gap-4">
        <div className={`w-14 h-14 rounded-xl flex items-center justify-center transition-colors ${
          dragOver ? 'bg-indigo-500/20' : 'bg-slate-700/80'
        }`}>
          {dragOver ? (
            <FileArchive className="w-7 h-7 text-indigo-400" />
          ) : (
            <Upload className="w-7 h-7 text-slate-400" />
          )}
        </div>
        <div>
          <p className="text-base font-semibold text-slate-200">
            Upload ZIP Archive
          </p>
          <p className="text-sm text-slate-400 mt-1">
            Drag & drop or click to browse
          </p>
          <p className="text-xs text-slate-500 mt-2">
            Max 100MB • Source code only
          </p>
        </div>
      </label>
    </div>
  );
}
