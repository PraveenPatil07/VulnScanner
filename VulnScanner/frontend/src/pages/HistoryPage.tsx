import { useNavigate } from 'react-router-dom';
import { ScanHistory } from '../components/ScanHistory';

export function HistoryPage() {
  const navigate = useNavigate();

  return (
    <main className="max-w-7xl mx-auto px-4 py-8">
      <ScanHistory
        onBack={() => navigate('/')}
        onSelectScan={(scanId) => navigate(`/report/${scanId}`)}
      />
    </main>
  );
}
