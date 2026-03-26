import React from 'react';

const Card = ({ children, title, icon: Icon, className = '', variant = 'default', withHover = true }) => {
  const baseClasses = `bg-white dark:bg-gray-800 rounded-xl border border-gray-200 dark:border-gray-700 
                       overflow-hidden transition-all duration-300 ${className}`;
  
  const hoverClasses = withHover ? 'hover:shadow-lg hover:border-gray-300 dark:hover:border-gray-600 hover:-translate-y-1' : '';
  
  const shadowClasses = variant === 'elevated' ? 'shadow-lg' : variant === 'base' ? 'shadow-base' : 'shadow-sm';

  return (
    <div className={`${baseClasses} ${hoverClasses} ${shadowClasses}`}>
      {title && (
        <div className="px-6 py-4 border-b border-gray-200 dark:border-gray-700 bg-gradient-to-r from-gray-50 to-gray-50/20 dark:from-gray-800/50 dark:to-gray-800/0">
          <div className="flex items-center gap-2">
            {Icon && <Icon className="w-5 h-5 text-primary" />}
            <h3 className="text-base font-600 text-gray-900 dark:text-gray-100">{title}</h3>
          </div>
        </div>
      )}
      <div className="p-6 text-gray-900 dark:text-gray-50">
        {children}
      </div>
    </div>
  );
};

export default Card;
