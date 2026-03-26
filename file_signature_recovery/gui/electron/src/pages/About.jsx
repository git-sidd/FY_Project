import React, { useState } from 'react';
import Card from '../components/ui/Card.jsx';
import Badge from '../components/ui/Badge.jsx';
import { Code, Zap, FileJson } from 'lucide-react';

const About = () => {
  const [results, setResults] = useState(null);

  const loadResults = async () => {
    try {
      const { ipcRenderer } = window.require('electron');
      const data = await ipcRenderer.invoke('read-results-json');
      
      if (data) {
        setResults(JSON.parse(data));
      } else {
        alert("Results file not found. Ensure train.py has been executed.");
      }
    } catch (err) {
      console.error(err);
      alert("Error reading results: " + err.message);
    }
  };

  const fileTypes = [
    { cat: 'Documents', types: ['PDF', 'DOCX', 'XLSX', 'PPTX', 'TXT', 'RTF'] },
    { cat: 'Images', types: ['JPEG', 'PNG', 'GIF', 'BMP', 'TIFF', 'WEBP'] },
    { cat: 'Video', types: ['MP4', 'AVI', 'MKV', 'MOV', 'WMV'] },
    { cat: 'Audio', types: ['MP3', 'WAV', 'FLAC', 'OGG'] },
    { cat: 'Archives', types: ['ZIP', 'RAR', '7Z', 'TAR', 'GZ'] },
    { cat: 'Executables', types: ['EXE', 'ELF', 'DLL', 'MACH-O'] },
    { cat: 'Database', types: ['SQLITE'] },
    { cat: 'Web', types: ['HTML', 'CSS', 'JS', 'JSON', 'XML'] }
  ];

  return (
    <div className="space-y-6 pb-12 animate-in fade-in duration-300">
      
      {/* SECTION 1: Project Info */}
      <Card title="File Signature Analysis & Recovering Deleted Files">
        <div className="space-y-5">
          <Badge variant="default">Version 1.0.0</Badge>
          <p className="text-gray-600 dark:text-gray-400">
            A specialized forensic tool leveraging deep learning and gradient boosting to perform robust file signature analysis. 
            It identifies disguised files, detects tampered digital signatures, and assesses malware risk entirely locally.
          </p>
          <div className="flex flex-wrap gap-2 pt-2">
             <Badge variant="primary">CNN</Badge>
             <Badge variant="primary">XGBoost</Badge>
             <Badge variant="info">SHAP</Badge>
             <Badge variant="success">FastAPI</Badge>
             <Badge variant="default">Electron</Badge>
             <Badge variant="default">React</Badge>
          </div>
        </div>
      </Card>

      {/* SECTION 2: Model Performance */}
      <Card title="Model Performance">
        <div className="space-y-4">
          <div className="overflow-x-auto rounded-lg border border-gray-200 dark:border-gray-700">
            <table className="min-w-full text-sm text-left">
              <thead className="text-xs text-gray-500 bg-gray-50 dark:bg-gray-800 dark:text-gray-400 uppercase">
                <tr>
                  <th className="px-6 py-3 border-b dark:border-gray-700">Model Architecture</th>
                  <th className="px-6 py-3 border-b dark:border-gray-700">Accuracy</th>
                  <th className="px-6 py-3 border-b dark:border-gray-700">F1 Score</th>
                </tr>
              </thead>
              <tbody>
                <tr className="border-b dark:border-gray-700 bg-white dark:bg-gray-900">
                  <td className="px-6 py-4 font-medium text-gray-900 dark:text-white">CNN alone</td>
                  <td className="px-6 py-4">{results?.cnn_accuracy ? `${results.cnn_accuracy.toFixed(1)}%` : '—'}</td>
                  <td className="px-6 py-4">{results?.cnn_f1 ? results.cnn_f1.toFixed(3) : '—'}</td>
                </tr>
                <tr className="border-b dark:border-gray-700 bg-white dark:bg-gray-900">
                  <td className="px-6 py-4 font-medium text-gray-900 dark:text-white">XGBoost alone</td>
                  <td className="px-6 py-4">{results?.xgb_accuracy ? `${results.xgb_accuracy.toFixed(1)}%` : '—'}</td>
                  <td className="px-6 py-4">{results?.xgb_f1 ? results.xgb_f1.toFixed(3) : '—'}</td>
                </tr>
                <tr className="bg-indigo-50 dark:bg-indigo-900/20">
                  <td className="px-6 py-4 font-bold text-indigo-600 dark:text-indigo-400">CNN + XGBoost</td>
                  <td className="px-6 py-4 font-bold text-indigo-600 dark:text-indigo-400">{results?.hybrid_accuracy ? `${results.hybrid_accuracy.toFixed(1)}%` : '—'}</td>
                  <td className="px-6 py-4 font-bold text-indigo-600 dark:text-indigo-400">{results?.hybrid_f1 ? results.hybrid_f1.toFixed(3) : '—'}</td>
                </tr>
              </tbody>
            </table>
          </div>
          
          <div className="flex items-center justify-between text-sm text-gray-500 dark:text-gray-400 mt-4 bg-gray-50 dark:bg-gray-800/50 p-3 rounded shadow-sm border border-gray-100 dark:border-gray-700">
            <p>Run <code className="bg-gray-200 dark:bg-gray-700 px-1 rounded text-red-500">train.py</code> to populate these values.</p>
            <button 
              onClick={loadResults}
              className="px-4 py-2 bg-white dark:bg-gray-700 hover:bg-gray-100 dark:hover:bg-gray-600 shadow-sm border border-gray-200 dark:border-gray-600 text-gray-700 dark:text-gray-300 rounded transition"
            >
              Load Results
            </button>
          </div>
        </div>
      </Card>

      {/* SECTION 4: How it Works */}
      <h3 className="text-xl font-bold text-gray-800 dark:text-gray-200 px-2 mt-8 mb-4">How it works</h3>
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <Card className="flex flex-col h-full bg-gradient-to-br from-white to-gray-50 dark:from-gray-800 dark:to-gray-800/80">
          <div className="flex items-center space-x-3 mb-4">
            <div className="p-2 bg-blue-100 dark:bg-blue-900/30 text-blue-600 rounded-lg"><Code className="w-6 h-6"/></div>
            <h4 className="font-semibold text-gray-900 dark:text-white">Step 1: File bytes extracted</h4>
          </div>
          <p className="text-sm text-gray-600 dark:text-gray-400">
            The first 512 bytes of the file are sequentially extracted and formatted into a fixed-length signature stream.
          </p>
        </Card>
        
        <Card className="flex flex-col h-full bg-gradient-to-br from-white to-gray-50 dark:from-gray-800 dark:to-gray-800/80">
          <div className="flex items-center space-x-3 mb-4">
            <div className="p-2 bg-indigo-100 dark:bg-indigo-900/30 text-indigo-600 rounded-lg"><Zap className="w-6 h-6"/></div>
            <h4 className="font-semibold text-gray-900 dark:text-white">Step 2: CNN + XGBoost analysis</h4>
          </div>
          <p className="text-sm text-gray-600 dark:text-gray-400">
            CNN abstracts hierarchical patterns while XGBoost extracts features resulting in accurate classification.
          </p>
        </Card>

        <Card className="flex flex-col h-full bg-gradient-to-br from-white to-gray-50 dark:from-gray-800 dark:to-gray-800/80">
          <div className="flex items-center space-x-3 mb-4">
            <div className="p-2 bg-green-100 dark:bg-green-900/30 text-green-600 rounded-lg"><FileJson className="w-6 h-6"/></div>
            <h4 className="font-semibold text-gray-900 dark:text-white">Step 3: SHAP explanation</h4>
          </div>
          <p className="text-sm text-gray-600 dark:text-gray-400">
            AI explains its thought process by mapping which exact bytes or engineered features led directly to its predicted result.
          </p>
        </Card>
      </div>

      {/* SECTION 3: Supported Formats */}
      <h3 className="text-xl font-bold text-gray-800 dark:text-gray-200 px-2 mt-8 mb-4">Supported file types</h3>
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        {fileTypes.map(category => (
          <div key={category.cat} className="bg-white dark:bg-gray-800 rounded-lg shadow-sm border border-gray-200 dark:border-gray-700 p-4">
            <h4 className="font-semibold text-xs text-gray-500 dark:text-gray-400 uppercase tracking-widest mb-3">{category.cat}</h4>
            <div className="flex flex-wrap gap-2">
              {category.types.map(t => (
                <span key={t} className="px-2 py-1 bg-gray-50 dark:bg-gray-900 text-gray-700 dark:text-gray-300 text-xs rounded shadow-sm border border-gray-200 dark:border-gray-700">
                  {t}
                </span>
              ))}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};

export default About;
