import React, { useState } from 'react';
import { useTheme } from './context/ThemeContext.jsx';
import { ShieldCheck, HardDrive, FileText, Info, Shield, Sun, Moon, Menu, X } from 'lucide-react';
import Badge from './components/ui/Badge.jsx';
import Card from './components/ui/Card.jsx';
import FileAnalyzer from './pages/FileAnalyzer.jsx';
import Recovery from './pages/Recovery.jsx';
import About from './pages/About.jsx';

function App() {
  const { theme, toggleTheme } = useTheme();
  const [activeTab, setActiveTab] = useState('analyzer');
  const [sidebarOpen, setSidebarOpen] = useState(true);

  const navItems = [
    { id: 'analyzer', label: 'File Analyzer', icon: ShieldCheck, description: 'Analyze files' },
    { id: 'recovery', label: 'Recovery', icon: HardDrive, description: 'Recover files' },
    { id: 'reports', label: 'Reports', icon: FileText, comingSoon: true, description: 'View reports' },
  ];

  return (
    <div className="flex h-screen w-full bg-gray-50 dark:bg-gray-900 text-gray-900 dark:text-gray-50 overflow-hidden">
      
      {/* SIDEBAR */}
      <aside className={`${sidebarOpen ? 'w-64' : 'w-20'} bg-white dark:bg-gray-950 border-r border-gray-200 dark:border-gray-800 
                        flex flex-col flex-shrink-0 transition-all duration-300 shadow-lg`}>
        
        {/* Header */}
        <div className="h-16 flex items-center justify-between px-4 border-b border-gray-200 dark:border-gray-800 shrink-0">
          {sidebarOpen && (
            <div className="flex items-center gap-2 min-w-0">
              <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-primary to-accent flex items-center justify-center flex-shrink-0">
                <Shield className="w-5 h-5 text-white" />
              </div>
              <div className="min-w-0">
                <h1 className="font-bold text-sm truncate text-gray-900 dark:text-white">File Signature</h1>
                <p className="text-xs text-gray-500 dark:text-gray-400 truncate">Analyzer</p>
              </div>
            </div>
          )}
          <button
            onClick={() => setSidebarOpen(!sidebarOpen)}
            className="p-1.5 hover:bg-gray-100 dark:hover:bg-gray-800 rounded-lg transition-colors flex-shrink-0"
            title={sidebarOpen ? 'Collapse sidebar' : 'Expand sidebar'}
          >
            {sidebarOpen ? <X className="w-5 h-5" /> : <Menu className="w-5 h-5" />}
          </button>
        </div>
        
        {/* Navigation */}
        <nav className="flex-1 overflow-y-auto py-4 px-2 space-y-1.5 scrollbar-thin">
          {navItems.map((item) => (
            <button
              key={item.id}
              onClick={() => !item.comingSoon && setActiveTab(item.id)}
              disabled={item.comingSoon}
              className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-lg font-medium text-sm 
                          transition-all duration-200 relative group ${
                activeTab === item.id 
                  ? 'bg-gradient-to-r from-primary to-accent text-white shadow-md' 
                  : item.comingSoon
                    ? 'text-gray-400 dark:text-gray-600 cursor-not-allowed'
                    : 'text-gray-700 dark:text-gray-400 hover:bg-gray-100 dark:hover:bg-gray-800'
              }`}
            >
              <item.icon className="w-5 h-5 flex-shrink-0" />
              {sidebarOpen && (
                <>
                  <div className="flex-1 text-left min-w-0">
                    <p className="truncate">{item.label}</p>
                  </div>
                  {item.comingSoon && (
                    <Badge size="sm" variant="warning" className="flex-shrink-0">Soon</Badge>
                  )}
                </>
              )}
              {!sidebarOpen && item.comingSoon && (
                <div className="absolute left-full ml-2 px-2 py-1 bg-gray-900 dark:bg-gray-100 text-white dark:text-gray-900 
                              text-xs rounded-lg opacity-0 group-hover:opacity-100 transition-opacity whitespace-nowrap pointer-events-none z-50">
                  Coming Soon
                </div>
              )}
            </button>
          ))}
        </nav>
        
        {/* Footer */}
        <div className="p-3 border-t border-gray-200 dark:border-gray-800 shrink-0 space-y-2.5">
          <button 
            onClick={() => setActiveTab('about')}
            className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-lg font-medium text-sm 
                        transition-colors ${
              activeTab === 'about'
                ? 'bg-gradient-to-r from-primary to-accent text-white'
                : 'text-gray-700 dark:text-gray-400 hover:bg-gray-100 dark:hover:bg-gray-800'
            }`}
          >
            <Info className="w-5 h-5 flex-shrink-0" />
            {sidebarOpen && 'About'}
          </button>
          <button 
            onClick={toggleTheme}
            className="w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium 
                      text-gray-700 dark:text-gray-400 hover:bg-gray-100 dark:hover:bg-gray-800 transition-colors"
            title="Toggle theme"
          >
            {theme === 'dark' ? (
              <>
                <Sun className="w-5 h-5 flex-shrink-0 text-yellow-500" />
                {sidebarOpen && 'Light Mode'}
              </>
            ) : (
              <>
                <Moon className="w-5 h-5 flex-shrink-0 text-indigo-600" />
                {sidebarOpen && 'Dark Mode'}
              </>
            )}
          </button>
        </div>
      </aside>

      {/* MAIN CONTENT AREA */}
      <main className="flex-1 flex flex-col min-w-0 overflow-hidden">
        
        {/* Header */}
        <header className="h-16 flex items-center justify-between px-6 bg-white dark:bg-gray-900 border-b 
                           border-gray-200 dark:border-gray-800 shrink-0 shadow-sm">
          <div className="flex items-center gap-3">
            <h2 className="text-lg font-bold text-gray-900 dark:text-white">
              {navItems.find(i => i.id === activeTab)?.label || 'About'}
            </h2>
            {activeTab === 'analyzer' && (
              <Badge variant="primary" size="sm" withPulse>Active</Badge>
            )}
          </div>
          <div className="flex items-center gap-3">
            <Badge variant="default" size="md" icon={Shield}>v1.0.0</Badge>
          </div>
        </header>

        {/* Content */}
        <div className="flex-1 overflow-y-auto scrollbar-thin">
          <div className="p-6 lg:p-8 max-w-7xl mx-auto w-full">
            {activeTab === 'analyzer' && <FileAnalyzer />}

            {activeTab === 'recovery' && <Recovery />}

            {activeTab === 'reports' && (
              <Card title="Historical Reports">
                <div className="text-center py-8">
                  <FileText className="w-12 h-12 mx-auto text-gray-400 mb-4" />
                  <p className="text-gray-600 dark:text-gray-400">
                    Detailed analysis reports and scanning history. Coming soon!
                  </p>
                </div>
              </Card>
            )}

            {activeTab === 'about' && <About />}
          </div>
        </div>
      </main>
    </div>
  );
}

export default App;
