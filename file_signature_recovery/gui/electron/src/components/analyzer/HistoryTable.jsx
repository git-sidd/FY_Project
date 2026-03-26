import React from 'react';
import Card from '../ui/Card.jsx';
import Badge from '../ui/Badge.jsx';
import { RefreshCw, Trash2 } from 'lucide-react';

const HistoryTable = ({ history, onReanalyze, onClear }) => {
  const TitleNode = (
    <div className="flex justify-between items-center w-full">
      <span>Analysis History</span>
      <button onClick={onClear} className="text-xs text-red-500 hover:text-red-700 flex items-center font-normal disabled:opacity-50" disabled={history.length === 0}>
        <Trash2 className="w-3 h-3 mr-1" /> Clear
      </button>
    </div>
  );

  return (
    <Card title={TitleNode} className="col-span-full">
      {history.length === 0 ? (
        <div className="text-center py-8 text-gray-500 dark:text-gray-400 text-sm">
          No files analyzed yet.
        </div>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-sm text-left whitespace-nowrap">
            <thead className="text-xs text-gray-500 uppercase bg-gray-50 dark:bg-gray-800/50 dark:text-gray-400">
              <tr>
                <th className="px-4 py-3">#</th>
                <th className="px-4 py-3">Filename</th>
                <th className="px-4 py-3">Type</th>
                <th className="px-4 py-3">Confidence</th>
                <th className="px-4 py-3">Risk</th>
                <th className="px-4 py-3">Status</th>
                <th className="px-4 py-3">Time (ms)</th>
                <th className="px-4 py-3">Action</th>
              </tr>
            </thead>
            <tbody>
              {history.map((item, idx) => {
                const isMismatch = item.declared_extension && item.predicted_file_type &&
                                  item.declared_extension.toLowerCase() !== `.${item.predicted_file_type.toLowerCase()}`;
                
                let statusVariant = 'success';
                let statusText = 'Valid';
                if (item.signature_tampered) { statusVariant = 'danger'; statusText = 'Corrupted'; }
                else if (isMismatch) { statusVariant = 'warning'; statusText = 'Mismatch'; }

                let riskVariant = 'success';
                if (item.risk_level === 'HIGH') riskVariant = 'danger';
                if (item.risk_level === 'MEDIUM') riskVariant = 'warning';

                return (
                  <tr 
                    key={idx} 
                    className="border-b dark:border-gray-700 hover:bg-gray-50 dark:hover:bg-gray-800/80 transition-colors"
                  >
                    <td className="px-4 py-3 text-gray-500">{history.length - idx}</td>
                    <td className="px-4 py-3 font-medium text-gray-900 dark:text-gray-200 truncate max-w-[200px]" title={item.filename}>
                      {item.filename}
                    </td>
                    <td className="px-4 py-3 font-semibold text-indigo-600 dark:text-indigo-400">{item.predicted_file_type}</td>
                    <td className="px-4 py-3">{(item.file_type_confidence * 100).toFixed(1)}%</td>
                    <td className="px-4 py-3">
                      <Badge variant={riskVariant}>{item.risk_level}</Badge>
                    </td>
                    <td className="px-4 py-3">
                      <Badge variant={statusVariant}>{statusText}</Badge>
                    </td>
                    <td className="px-4 py-3 text-gray-500">{item.analysis_time_ms}</td>
                    <td className="px-4 py-3">
                      <button 
                        onClick={() => onReanalyze(item)}
                        className="text-indigo-600 dark:text-indigo-400 hover:text-indigo-800 flex items-center transition"
                      >
                        <RefreshCw className="w-4 h-4 mr-1" /> View
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </Card>
  );
};

export default HistoryTable;
