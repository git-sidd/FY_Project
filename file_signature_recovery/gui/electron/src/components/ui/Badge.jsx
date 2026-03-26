import React from 'react';

const Badge = ({ children, variant = 'default', className = '', size = 'md', icon: Icon, withPulse = false }) => {
  const baseClasses = 'inline-flex items-center font-medium rounded-full transition-all duration-200';
  
  const sizeClasses = {
    sm: 'px-2 py-1 text-xs',
    md: 'px-3 py-1.5 text-xs',
    lg: 'px-4 py-2 text-sm',
  };

  const variants = {
    default: 'bg-gray-100 text-gray-800 dark:bg-gray-800 dark:text-gray-300 border border-gray-200 dark:border-gray-700',
    primary: 'bg-primary/10 text-primary dark:bg-primary/20 dark:text-primary-light border border-primary/20 dark:border-primary/30',
    success: 'bg-success/10 text-success dark:bg-success/20 border border-success/20 dark:border-success/30',
    warning: 'bg-warning/10 text-warning dark:bg-warning/20 border border-warning/20 dark:border-warning/30',
    danger: 'bg-danger/10 text-danger dark:bg-danger/20 border border-danger/20 dark:border-danger/30',
    info: 'bg-blue-100/50 text-blue-800 dark:bg-blue-500/10 dark:text-blue-400 border border-blue-200/50 dark:border-blue-500/20',
  };

  const variantClass = variants[variant] || variants.default;
  const sizeClass = sizeClasses[size] || sizeClasses.md;
  const pulseClass = withPulse ? 'animate-pulse-soft' : '';

  return (
    <span className={`${baseClasses} ${sizeClass} ${variantClass} ${pulseClass} ${className}`}>
      {Icon && <Icon className="w-3.5 h-3.5 mr-1" />}
      {children}
    </span>
  );
};

export default Badge;
