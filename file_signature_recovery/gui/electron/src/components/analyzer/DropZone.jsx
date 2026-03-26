import React, { useCallback, useState } from 'react';
import { UploadCloud, File as FileIcon, AlertCircle } from 'lucide-react';
import LoadingSpinner from '../ui/LoadingSpinner.jsx';

const DropZone = ({ onAnalyze, isLoading, error }) => {
  const [isDragging, setIsDragging] = useState(false);
  const [selectedFile, setSelectedFile] = useState(null);

  const handleDragOver = (e) => {
    e.preventDefault();
    setIsDragging(true);
  };

  const handleDragLeave = (e) => {
    e.preventDefault();
    setIsDragging(false);
  };

  const handleDrop = useCallback((e) => {
    e.preventDefault();
    setIsDragging(false);
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      const file = e.dataTransfer.files[0];
      setSelectedFile(file);
      onAnalyze(file);
    }
  }, [onAnalyze]);

  const handleFileChange = (e) => {
    if (e.target.files && e.target.files.length > 0) {
      const file = e.target.files[0];
      setSelectedFile(file);
      onAnalyze(file);
    }
  };

  const formatFileSize = (bytes) => {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  };

  return (
    <div className="w-full animate-fade-in">
      <label
        onDragOver={handleDragOver}
        onDragLeave={handleDragLeave}
        onDrop={handleDrop}
        className={`relative flex flex-col items-center justify-center w-full h-72 
                    border-2 border-dashed rounded-xl cursor-pointer transition-all duration-300
                    ${isDragging 
                      ? 'border-primary bg-primary/5 dark:bg-primary/10 scale-[1.02]' 
                      : error 
                        ? 'border-danger bg-danger/5 dark:bg-danger/10'
                        : 'border-gray-300 dark:border-gray-700 bg-gradient-to-br from-gray-50 to-white dark:from-gray-800 dark:to-gray-900 hover:border-primary/50 dark:hover:border-primary/30 hover:bg-gradient-to-br hover:from-primary/5 hover:to-primary/0'
                    }`}
      >
        <input 
          type="file" 
          className="hidden" 
          onChange={handleFileChange} 
          disabled={isLoading} 
        />
        
        {isLoading ? (
          <LoadingSpinner label="Analyzing file..." />
        ) : (
          <div className="flex flex-col items-center justify-center pt-5 pb-6 text-center px-6">
            <div className={`w-16 h-16 rounded-full flex items-center justify-center mb-4 transition-all duration-300
                            ${isDragging 
                              ? 'bg-primary/20 text-primary scale-110' 
                              : error 
                                ? 'bg-danger/20 text-danger' 
                                : 'bg-gray-100 dark:bg-gray-800 text-gray-600 dark:text-gray-400'
                            }`}>
              <UploadCloud className="w-8 h-8" />
            </div>

            <h3 className="mb-2 text-lg font-semibold text-gray-900 dark:text-white">
              Drop your file here
            </h3>
            <p className="mb-4 text-sm text-gray-600 dark:text-gray-400">
              or click to browse your computer for any file type
            </p>

            <div className="inline-flex items-center px-4 py-2 rounded-full bg-gray-100 dark:bg-gray-800 text-xs font-medium text-gray-700 dark:text-gray-300">
              <span className="w-2 h-2 rounded-full bg-primary mr-2"></span>
              Supports all file formats
            </div>

            {selectedFile && (
              <div className="mt-6 w-full max-w-xs animate-slide-up">
                <div className="flex items-center gap-3 p-3 rounded-lg bg-primary/10 dark:bg-primary/15 border border-primary/20 dark:border-primary/30">
                  <FileIcon className="w-5 h-5 text-primary flex-shrink-0" />
                  <div className="flex-1 min-w-0 text-left">
                    <p className="text-sm font-medium text-primary truncate">{selectedFile.name}</p>
                    <p className="text-xs text-gray-600 dark:text-gray-400">{formatFileSize(selectedFile.size)}</p>
                  </div>
                </div>
              </div>
            )}

            {error && (
              <div className="mt-6 w-full max-w-xs animate-slide-up">
                <div className="flex items-start gap-3 p-3 rounded-lg bg-danger/10 dark:bg-danger/15 border border-danger/20 dark:border-danger/30">
                  <AlertCircle className="w-5 h-5 text-danger flex-shrink-0 mt-0.5" />
                  <p className="text-sm text-danger font-medium">{error}</p>
                </div>
              </div>
            )}
          </div>
        )}
      </label>
    </div>
  );
};

export default DropZone;
