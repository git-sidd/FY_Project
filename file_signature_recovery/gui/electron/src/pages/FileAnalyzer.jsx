import React, { useState } from 'react';
import axios from 'axios';
import DropZone from '../components/analyzer/DropZone.jsx';
import ResultSummary from '../components/analyzer/ResultSummary.jsx';
import RiskGauge from '../components/analyzer/RiskGauge.jsx';
import ShapChart from '../components/analyzer/ShapChart.jsx';
import ConfidenceBars from '../components/analyzer/ConfidenceBars.jsx';
import HistoryTable from '../components/analyzer/HistoryTable.jsx';
import Card from '../components/ui/Card.jsx';
import { Shield, Zap, Lock, Brain } from 'lucide-react';

const FileAnalyzer = () => {
  const [currentResult, setCurrentResult] = useState(null);
  const [history, setHistory] = useState([]);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState(null);

  const analyzeFile = async (file) => {
    setIsLoading(true);
    setError(null);
    try {
      const formData = new FormData();
      formData.append('file', file);
      
      const response = await axios.post('http://127.0.0.1:7999/analyze', formData, {
        headers: { 'Content-Type': 'multipart/form-data' }
      });
      
      const result = response.data;
      setCurrentResult(result);
      
      setHistory(prev => {
        const newHistory = [result, ...prev];
        return newHistory.slice(0, 20); // max 20
      });
    } catch (err) {
      console.error(err);
      setError(err.response?.data?.detail || err.message || 'Error connecting to analysis server.');
    } finally {
      setIsLoading(false);
    }
  };

  const loadHistoryItem = (item) => {
    setCurrentResult(item);
    window.scrollTo({ top: 0, behavior: 'smooth' });
  };

  const clearHistory = () => {
    setHistory([]);
    setCurrentResult(null);
  };

  return (
    <div className="space-y-6 pb-12">
      {/* Welcome Section */}
      {!currentResult && !isLoading && (
        <div className="animate-fade-in">
          {/* Hero Card */}
          <Card variant="elevated" withHover={false} className="bg-gradient-to-br from-primary/10 via-primary/5 to-accent/5 dark:from-primary/20 dark:via-primary/10 dark:to-accent/20 border-primary/20 dark:border-primary/30">
            <div className="text-center py-12 px-8">
              <div className="w-16 h-16 rounded-full bg-gradient-to-br from-primary to-accent flex items-center justify-center mx-auto mb-6 shadow-lg">
                <Shield className="w-8 h-8 text-white" />
              </div>
              <h2 className="text-3xl md:text-4xl font-bold text-gradient mb-4">
                File Signature Analysis
              </h2>
              <p className="text-gray-600 dark:text-gray-300 max-w-2xl mx-auto text-lg leading-relaxed mb-8">
                Advanced machine learning-powered file analysis that examines file signatures, detects anomalies, 
                and identifies potential threats with high accuracy.
              </p>
              
              {/* Features Grid */}
              <div className="grid grid-cols-3 gap-4 mb-8 max-w-2xl mx-auto">
                {[
                  { icon: Brain, label: 'AI Powered', desc: 'CNN + XGBoost' },
                  { icon: Lock, label: 'Secure', desc: 'Local Analysis' },
                  { icon: Zap, label: 'Fast', desc: 'Real-time Results' },
                ].map((feature, idx) => (
                  <div key={idx} className="flex flex-col items-center">
                    <feature.icon className="w-6 h-6 text-primary mb-2" />
                    <p className="text-sm font-semibold text-gray-900 dark:text-white">{feature.label}</p>
                    <p className="text-xs text-gray-500 dark:text-gray-400">{feature.desc}</p>
                  </div>
                ))}
              </div>
              
              <div className="max-w-2xl mx-auto">
                <DropZone onAnalyze={analyzeFile} isLoading={isLoading} error={error} />
              </div>
            </div>
          </Card>
        </div>
      )}

      {/* Analysis Results View */}
      {(currentResult || isLoading) && (
        <div className="animate-fade-in">
          {/* Upload Area + Results Summary */}
          <div className="grid grid-cols-1 lg:grid-cols-5 gap-6">
            {/* Left Column - Upload & Summary */}
            <div className="lg:col-span-2 flex flex-col gap-6">
              <div>
                <h3 className="text-sm uppercase font-bold tracking-wider text-gray-500 dark:text-gray-400 mb-3">
                  New Analysis
                </h3>
                <DropZone onAnalyze={analyzeFile} isLoading={isLoading} error={error} />
              </div>
              
              {currentResult && (
                <div>
                  <h3 className="text-sm uppercase font-bold tracking-wider text-gray-500 dark:text-gray-400 mb-3">
                    Analysis Summary
                  </h3>
                  <ResultSummary result={currentResult} />
                </div>
              )}
            </div>

            {/* Right Column - Visualizations */}
            {currentResult && (
              <div className="lg:col-span-3 flex flex-col gap-6">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                  <div>
                    <h3 className="text-sm uppercase font-bold tracking-wider text-gray-500 dark:text-gray-400 mb-3">
                      Risk Assessment
                    </h3>
                    <RiskGauge score={currentResult?.malware_risk_score || 0} />
                  </div>
                  <div>
                    <h3 className="text-sm uppercase font-bold tracking-wider text-gray-500 dark:text-gray-400 mb-3">
                      Type Confidence
                    </h3>
                    <ConfidenceBars confidenceDict={currentResult?.confidence_per_type} />
                  </div>
                </div>

                <div>
                  <h3 className="text-sm uppercase font-bold tracking-wider text-gray-500 dark:text-gray-400 mb-3">
                    Feature Importance
                  </h3>
                  <ShapChart features={currentResult?.top_shap_features} />
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Analysis History */}
      {history.length > 0 && (
        <div className="animate-fade-in">
          <h3 className="text-sm uppercase font-bold tracking-wider text-gray-500 dark:text-gray-400 mb-4">
            Analysis History
          </h3>
          <HistoryTable 
            history={history} 
            onReanalyze={loadHistoryItem} 
            onClear={clearHistory} 
          />
        </div>
      )}
    </div>
  );
};

export default FileAnalyzer;
