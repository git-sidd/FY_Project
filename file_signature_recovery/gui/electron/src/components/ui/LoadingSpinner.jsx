import React from 'react';
import { Loader2 } from 'lucide-react';

const LoadingSpinner = ({ label = 'Loading...', variant = 'default', size = 'md' }) => {
  const sizeClasses = {
    sm: 'w-6 h-6',
    md: 'w-8 h-8',
    lg: 'w-12 h-12',
  };

  const containerVariants = {
    default: 'flex flex-col items-center justify-center space-y-3',
    overlay: 'fixed inset-0 flex flex-col items-center justify-center bg-black/20 dark:bg-black/40 backdrop-blur-sm space-y-4',
  };

  return (
    <div className={containerVariants[variant]}>
      <div className="relative">
        <Loader2 className={`${sizeClasses[size]} text-primary animate-spin`} />
        <div className={`${sizeClasses[size]} absolute inset-0 bg-gradient-to-r from-primary/20 to-transparent rounded-full blur`}></div>
      </div>
      {label && (
        <div className="text-center">
          <p className="text-sm font-semibold text-gray-900 dark:text-white">{label}</p>
          <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">Please wait...</p>
        </div>
      )}
    </div>
  );
};

export default LoadingSpinner;
