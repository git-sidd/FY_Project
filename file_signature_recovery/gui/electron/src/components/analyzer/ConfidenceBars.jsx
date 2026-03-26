import React, { useEffect, useState } from 'react';
import Card from '../ui/Card.jsx';

const ConfidenceBars = ({ confidenceDict }) => {
  const [animated, setAnimated] = useState(false);

  useEffect(() => {
    setAnimated(false);
    const timer = setTimeout(() => {
      setAnimated(true);
    }, 50);
    return () => clearTimeout(timer);
  }, [confidenceDict]);

  if (!confidenceDict) return null;

  const items = Object.entries(confidenceDict)
    .map(([type, score]) => ({ type, score }))
    .sort((a, b) => b.score - a.score)
    .slice(0, 5);

  return (
    <Card title="Top 5 Predicted Types" className="h-full">
      <div className="space-y-4">
        {items.map((item, idx) => {
          const pct = (item.score * 100).toFixed(1);
          const isTop = idx === 0;
          return (
            <div key={item.type} className="flex flex-col space-y-1">
              <div className="flex justify-between text-sm">
                <span className={`font-medium ${isTop ? 'text-indigo-600 dark:text-indigo-400' : 'text-gray-700 dark:text-gray-300'}`}>
                  {item.type}
                </span>
                <span className="text-gray-500 dark:text-gray-400">{pct}%</span>
              </div>
              <div className="w-full h-2 bg-gray-200 dark:bg-gray-700 rounded-full overflow-hidden">
                <div 
                  className={`h-full rounded-full transition-all duration-700 ease-out ${
                    isTop ? 'bg-indigo-500' : 'bg-gray-400 dark:bg-gray-500 opacity-70'
                  }`}
                  style={{ width: animated ? `${item.score * 100}%` : '0%' }}
                />
              </div>
            </div>
          );
        })}
      </div>
    </Card>
  );
};

export default ConfidenceBars;
