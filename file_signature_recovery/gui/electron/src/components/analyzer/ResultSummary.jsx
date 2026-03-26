import React from 'react';
import { CheckCircle, AlertTriangle, XCircle, FileType, ShieldAlert, File, Clock } from 'lucide-react';
import Card from '../ui/Card.jsx';
import Badge from '../ui/Badge.jsx';

const formatBytes = (bytes) => {
  if (bytes === 0) return '0 Bytes';
  const k = 1024;
  const sizes = ['Bytes', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
};

const ResultSummary = ({ result }) => {
  if (!result) return null;

  const {
    predicted_file_type,
    file_type_confidence,
    malware_risk_score,
    risk_level,
    signature_tampered,
    label_name,
    filename,
    file_size_bytes,
    declared_extension,
    analysis_time_ms
  } = result;

  const isMismatch = declared_extension && predicted_file_type && 
                     declared_extension.toLowerCase() !== `.${predicted_file_type.toLowerCase()}`;

  const getStatus = () => {
    if (signature_tampered) return { text: 'Corrupted', icon: XCircle, color: 'danger', variant: 'danger' };
    if (isMismatch) return { text: 'Mismatch', icon: AlertTriangle, color: 'warning', variant: 'warning' };
    return { text: 'Valid', icon: CheckCircle, color: 'success', variant: 'success' };
  };

  const getRiskBadgeVariant = () => {
    if (risk_level === 'HIGH') return 'danger';
    if (risk_level === 'MEDIUM') return 'warning';
    return 'success';
  };

  const status = getStatus();

  return (
    <div className="space-y-4 animate-fade-in">
      {/* Main Summary Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Card 1: Predicted File Type */}
        <Card variant="elevated" withHover className="flex flex-col items-center justify-center p-8 text-center">
          <div className="w-12 h-12 rounded-full bg-primary/10 flex items-center justify-center mb-4">
            <FileType className="w-6 h-6 text-primary" />
          </div>
          <div className="text-xs uppercase font-bold tracking-wider text-gray-500 dark:text-gray-400 mb-2">
            Predicted File Type
          </div>
          <div className="text-4xl font-bold text-gradient mb-3">
            {predicted_file_type || 'UNKNOWN'}
          </div>
          <Badge variant="primary" size="md">
            {(file_type_confidence * 100).toFixed(1)}% Confidence
          </Badge>
        </Card>

        {/* Card 2: Security Assessment */}
        <Card variant="elevated" withHover className="flex flex-col items-center justify-center p-8 text-center">
          <div className={`w-12 h-12 rounded-full flex items-center justify-center mb-4 
                          ${risk_level === 'HIGH' ? 'bg-danger/10' : risk_level === 'MEDIUM' ? 'bg-warning/10' : 'bg-success/10'}`}>
            <ShieldAlert className={`w-6 h-6 
              ${risk_level === 'HIGH' ? 'text-danger' : risk_level === 'MEDIUM' ? 'text-warning' : 'text-success'}`} />
          </div>
          <div className="text-xs uppercase font-bold tracking-wider text-gray-500 dark:text-gray-400 mb-2">
            Malware Risk Assessment
          </div>
          <div className={`text-3xl font-bold mb-3
            ${risk_level === 'HIGH' ? 'text-danger' : risk_level === 'MEDIUM' ? 'text-warning' : 'text-success'}`}>
            {risk_level}
          </div>
          <Badge variant={getRiskBadgeVariant()} size="md" withPulse={risk_level === 'HIGH'}>
            Risk Score: {(malware_risk_score * 100).toFixed(1)}%
          </Badge>
        </Card>
      </div>

      {/* Secondary Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Signature Status */}
        <Card withHover className="flex flex-col items-center justify-center p-6">
          <div className={`w-10 h-10 rounded-full flex items-center justify-center mb-3
                          ${status.variant === 'danger' ? 'bg-danger/10' : status.variant === 'warning' ? 'bg-warning/10' : 'bg-success/10'}`}>
            <status.icon className={`w-5 h-5
              ${status.variant === 'danger' ? 'text-danger' : status.variant === 'warning' ? 'text-warning' : 'text-success'}`} />
          </div>
          <div className="text-xs uppercase font-bold tracking-wider text-gray-500 dark:text-gray-400 mb-2">
            Signature Status
          </div>
          <div className={`text-lg font-bold mb-1
            ${status.variant === 'danger' ? 'text-danger' : status.variant === 'warning' ? 'text-warning' : 'text-success'}`}>
            {status.text}
          </div>
          <Badge variant={status.variant} size="sm">
            {label_name}
          </Badge>
        </Card>

        {/* File Information */}
        <Card withHover className="flex flex-col items-center justify-center p-6">
          <div className="w-10 h-10 rounded-full bg-blue-100 dark:bg-blue-900/30 flex items-center justify-center mb-3">
            <File className="w-5 h-5 text-blue-600 dark:text-blue-400" />
          </div>
          <div className="text-xs uppercase font-bold tracking-wider text-gray-500 dark:text-gray-400 mb-2">
            File Details
          </div>
          <p className="text-sm font-semibold text-gray-800 dark:text-gray-200 text-center truncate w-full px-1 mb-1">
            {filename}
          </p>
          <div className="text-xs text-gray-600 dark:text-gray-400 text-center">
            <span className="block">{formatBytes(file_size_bytes)}</span>
            <span className="block">Ext: {declared_extension || 'unknown'}</span>
          </div>
        </Card>

        {/* Analysis Stats */}
        <Card withHover className="flex flex-col items-center justify-center p-6">
          <div className="w-10 h-10 rounded-full bg-purple-100 dark:bg-purple-900/30 flex items-center justify-center mb-3">
            <Clock className="w-5 h-5 text-purple-600 dark:text-purple-400" />
          </div>
          <div className="text-xs uppercase font-bold tracking-wider text-gray-500 dark:text-gray-400 mb-2">
            Analysis Speed
          </div>
          <div className="text-2xl font-bold text-purple-600 dark:text-purple-400 mb-1">
            {analysis_time_ms ? `${analysis_time_ms}ms` : 'N/A'}
          </div>
          <Badge variant="default" size="sm">
            Hybrid ML Model
          </Badge>
        </Card>
      </div>
    </div>
  );
};

export default ResultSummary;
