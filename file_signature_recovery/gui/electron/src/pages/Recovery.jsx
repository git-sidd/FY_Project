import React, { useState, useEffect, useRef } from 'react';
import axios from 'axios';
import { 
  Search, 
  RotateCcw, 
  Database, 
  Trash2, 
  Folder, 
  ShieldAlert, 
  CheckCircle2, 
  Loader2, 
  FileSearch,
  AlertTriangle,
  ExternalLink,
  ChevronRight
} from 'lucide-react';
import Card from '../components/ui/Card.jsx';
import Badge from '../components/ui/Badge.jsx';

const Recovery = () => {
  // Form State
  const [path, setPath] = useState('');
  const [recursive, setRecursive] = useState(true);
  const [includeRB, setIncludeRB] = useState(false);
  const [includeDisk, setIncludeDisk] = useState(false);
  
  // Status State
  const [isScanning, setIsScanning] = useState(false);
  const [status, setStatus] = useState({
    progress: 0,
    total: 0,
    message: '',
    results: [],
    running: false
  });
  const [error, setError] = useState(null);
  const [isAdmin, setIsAdmin] = useState(false);

  const pollInterval = useRef(null);

  // Check health and admin status on mount
  useEffect(() => {
    const checkHealth = async () => {
      try {
        const res = await axios.get('http://127.0.0.1:7999/health');
        // main.py doesn't return admin status in /health yet, but we'll adapt if it did
        // For now, we'll assume it's checked during disk scan
      } catch (err) {
        console.error('API Health check failed:', err);
      }
    };
    checkHealth();
    
    return () => {
      if (pollInterval.current) clearInterval(pollInterval.current);
    };
  }, []);

  const startRecovery = async () => {
    if (!path) {
      setError('Please provide a folder path to scan.');
      return;
    }

    // Clear previous results as requested
    setStatus({
      progress: 0,
      total: 0,
      message: 'Initializing...',
      results: [],
      running: true
    });
    setIsScanning(true);
    setError(null);

    try {
      const res = await axios.post('http://127.0.0.1:7999/recover', {
        path,
        recursive,
        include_recycle_bin: includeRB,
        include_disk_scan: includeDisk
      });

      if (res.data.error) {
        setError(res.data.error);
        setIsScanning(false);
        return;
      }

      // Start polling
      pollInterval.current = setInterval(fetchStatus, 1000);
    } catch (err) {
      setError(err.response?.data?.detail || err.message || 'Failed to connect to API server.');
      setIsScanning(false);
    }
  };

  const fetchStatus = async () => {
    try {
      const res = await axios.get('http://127.0.0.1:7999/recover/status');
      const data = res.data;
      
      setStatus(data);

      if (!data.running) {
        if (pollInterval.current) {
          clearInterval(pollInterval.current);
          pollInterval.current = null;
        }
        setIsScanning(false);
      }
    } catch (err) {
      console.error('Polling error:', err);
    }
  };

  const calculatePercent = () => {
    if (status.total === 0) {
        if (status.message?.includes('Disk Carving')) return 50;
        if (status.message?.includes('Scanning')) return 10;
        return 0;
    }
    return Math.round((status.progress / status.total) * 100);
  };

  const getSourceBadge = (source) => {
    switch (source) {
      case 'disk_scan':
        return <Badge variant="info" icon={Database} size="sm">DISK</Badge>;
      case 'recycle_bin':
        return <Badge variant="warning" icon={Trash2} size="sm">BIN</Badge>;
      default:
        return <Badge variant="default" icon={Folder} size="sm">FOLD</Badge>;
    }
  };

  const getActionBadge = (action) => {
    switch (action) {
      case 'recovered':
        return <Badge variant="success" icon={CheckCircle2} size="sm">Recovered</Badge>;
      case 'quarantined':
        return <Badge variant="danger" icon={ShieldAlert} size="sm">Quarantined</Badge>;
      default:
        return <Badge variant="warning" icon={AlertTriangle} size="sm">Error</Badge>;
    }
  };

  return (
    <div className="space-y-6 animate-fade-in relative pb-10">
      
      {/* 1. Configuration Section */}
      <Card title="Recovery Configuration" icon={Search}>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6 items-end">
          <div className="space-y-2">
            <label className="text-sm font-semibold text-gray-700 dark:text-gray-300 ml-1">
              Primary Scan Path
            </label>
            <div className="relative group">
              <Folder className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400 group-focus-within:text-primary transition-colors" />
              <input 
                type="text" 
                value={path}
                onChange={(e) => setPath(e.target.value)}
                placeholder="C:\Users\YourUser\Documents..."
                className="w-full pl-10 pr-4 py-2 bg-gray-50 dark:bg-gray-900/50 border border-gray-200 dark:border-gray-700 rounded-lg 
                           focus:ring-2 focus:ring-primary/20 focus:border-primary outline-none transition-all dark:text-white"
                disabled={isScanning}
              />
            </div>
          </div>
          
          <div className="flex flex-wrap gap-4 mb-1">
            <label className="flex items-center gap-2 cursor-pointer group">
              <input 
                 type="checkbox" 
                 checked={recursive} 
                 onChange={(e) => setRecursive(e.target.checked)}
                 className="w-4 h-4 rounded border-gray-300 text-primary focus:ring-primary"
                 disabled={isScanning}
              />
              <span className="text-sm text-gray-600 dark:text-gray-400 group-hover:text-gray-900 dark:group-hover:text-gray-200 transition-colors">Recursive</span>
            </label>
            <label className="flex items-center gap-2 cursor-pointer group">
              <input 
                 type="checkbox" 
                 checked={includeRB} 
                 onChange={(e) => setIncludeRB(e.target.checked)}
                 className="w-4 h-4 rounded border-gray-300 text-primary focus:ring-primary"
                 disabled={isScanning}
              />
              <span className="text-sm text-gray-600 dark:text-gray-400 group-hover:text-gray-900 dark:group-hover:text-gray-200 transition-colors">Recycle Bin</span>
            </label>
            <label className="flex items-center gap-2 cursor-pointer group">
              <input 
                 type="checkbox" 
                 checked={includeDisk} 
                 onChange={(e) => setIncludeDisk(e.target.checked)}
                 className="w-4 h-4 rounded border-gray-300 text-primary focus:ring-primary"
                 disabled={isScanning}
              />
              <span className="text-sm text-gray-600 dark:text-gray-400 group-hover:text-gray-900 dark:group-hover:text-gray-200 transition-colors">Raw Disk Scan</span>
              <Badge variant="default" size="sm" className="opacity-70">Admin Req.</Badge>
            </label>
          </div>
        </div>

        {error && (
          <div className="mt-4 p-3 bg-danger/10 border border-danger/20 rounded-lg flex items-center gap-3 text-danger text-sm">
            <AlertTriangle className="w-4 h-4 shrink-0" />
            {error}
          </div>
        )}

        <div className="mt-6 flex justify-end">
          <button
            onClick={startRecovery}
            disabled={isScanning}
            className={`px-6 py-2.5 rounded-lg font-bold text-sm flex items-center gap-2 transition-all shadow-md
                        ${isScanning 
                          ? 'bg-gray-100 dark:bg-gray-800 text-gray-400 cursor-not-allowed' 
                          : 'bg-gradient-to-r from-primary to-accent text-white hover:shadow-lg hover:-translate-y-0.5 active:translate-y-0'}`}
          >
            {isScanning ? (
              <>
                <Loader2 className="w-4 h-4 animate-spin" />
                Recovering...
              </>
            ) : (
              <>
                <RotateCcw className="w-4 h-4" />
                Start Recovery
              </>
            )}
          </button>
        </div>
      </Card>

      {/* 2. Progress Section */}
      {(isScanning || status.message === 'Recovery complete! See Results tab.') && (
        <Card title="Scan Progress" variant="base">
          <div className="space-y-4">
             <div className="flex justify-between items-end mb-1">
                <div className="space-y-1">
                   <p className="text-sm font-semibold text-primary">{status.message}</p>
                   <p className="text-xs text-gray-500 dark:text-gray-400">
                     {status.total > 0 ? `Stage: ${status.progress} / ${status.total} items processed` : 'Stage: Phase transition...'}
                   </p>
                </div>
                <p className="text-lg font-bold text-primary">{calculatePercent()}%</p>
             </div>
             
             <div className="w-full bg-gray-100 dark:bg-gray-950 rounded-full h-2.5 overflow-hidden border border-gray-200 dark:border-gray-800">
                <div 
                  className="bg-gradient-to-r from-primary to-accent h-full transition-all duration-500 ease-out relative"
                  style={{ width: `${calculatePercent()}%` }}
                >
                  <div className="absolute inset-0 bg-white/20 animate-shimmer scale-x-150 origin-left" />
                </div>
             </div>
          </div>
        </Card>
      )}

      {/* 3. Results Section */}
      {status.results?.length > 0 && (
        <div className="animate-fade-in space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-sm uppercase font-bold tracking-wider text-gray-500 dark:text-gray-400">
              Recovery Results
            </h3>
            <div className="flex gap-3">
              <Badge variant="success" size="sm">{status.results.filter(r => r.action === 'recovered').length} Recovered</Badge>
              <Badge variant="danger" size="sm">{status.results.filter(r => r.action === 'quarantined').length} Quarantined</Badge>
            </div>
          </div>

          <Card variant="elevated" withHover={false} className="p-0">
            <div className="overflow-x-auto min-h-[400px]">
              <table className="w-full border-collapse">
                <thead>
                  <tr className="bg-gray-50 dark:bg-gray-900/50 border-b border-gray-200 dark:border-gray-800 text-left">
                    <th className="px-6 py-3 text-xs font-bold text-gray-500 uppercase tracking-wider">File Name</th>
                    <th className="px-6 py-3 text-xs font-bold text-gray-500 uppercase tracking-wider">Predicted Type</th>
                    <th className="px-6 py-3 text-xs font-bold text-gray-500 uppercase tracking-wider text-center">Source</th>
                    <th className="px-6 py-3 text-xs font-bold text-gray-500 uppercase tracking-wider">Confidence</th>
                    <th className="px-6 py-3 text-xs font-bold text-gray-500 uppercase tracking-wider text-center">Action</th>
                    <th className="px-6 py-3 text-xs font-bold text-gray-500 uppercase tracking-wider text-right">Preview</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-100 dark:divide-gray-800">
                  {status.results.map((file, idx) => (
                    <tr key={idx} className="hover:bg-gray-50/50 dark:hover:bg-gray-800/30 transition-colors group">
                      <td className="px-6 py-4 whitespace-nowrap min-w-[200px]">
                        <div className="flex items-center gap-3">
                          <div className="w-8 h-8 rounded-lg bg-primary/5 flex items-center justify-center text-primary group-hover:bg-primary/10 transition-colors">
                            <FileSearch className="w-4 h-4" />
                          </div>
                          <div className="min-w-0">
                            <p className="text-sm font-semibold truncate text-gray-900 dark:text-gray-100 max-w-[150px]" title={file.filename}>
                              {file.filename}
                            </p>
                            <p className="text-[10px] text-gray-400 truncate max-w-[150px]" title={file.filepath}>
                              {file.filepath}
                            </p>
                          </div>
                        </div>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap">
                        <span className="text-sm font-medium text-accent">{file.predicted_type}</span>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-center">
                        {getSourceBadge(file.source)}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap">
                        <div className="w-24 bg-gray-100 dark:bg-gray-900 h-1.5 rounded-full overflow-hidden">
                           <div className="bg-primary h-full" style={{ width: `${file.confidence}%` }} />
                        </div>
                        <span className="text-[10px] text-gray-500">{file.confidence}% match</span>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-center text-sm">
                        {getActionBadge(file.action)}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-right text-sm">
                         {file.output_path && (
                           <button className="p-1.5 hover:bg-primary/10 rounded text-primary transition-colors" title="Open containing folder">
                              <ExternalLink className="w-4 h-4" />
                           </button>
                         )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Card>
        </div>
      )}

      {!isScanning && !status.results?.length && (
        <div className="flex flex-col items-center justify-center py-20 text-center opacity-40">
           <FileSearch className="w-16 h-16 mb-4 text-gray-400" />
           <p className="text-gray-500 font-medium">Ready for scanning. Enter a path above to begin.</p>
           <p className="text-xs text-gray-400 mt-1 max-w-xs">Select "Raw Disk Scan" and run as Admin to find permanently deleted files.</p>
        </div>
      )}

    </div>
  );
};

export default Recovery;
