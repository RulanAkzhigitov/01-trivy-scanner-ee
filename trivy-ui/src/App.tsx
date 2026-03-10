import { BrowserRouter, Routes, Route, Link, Navigate } from 'react-router-dom';
import { ConfigsPage } from './pages/ConfigsPage';
import { JobsPage } from './pages/JobsPage';
import { JobDetailPage } from './pages/JobDetailPage';
import { QuickScanPage } from './pages/QuickScanPage';
import { Toaster } from '@/components/ui/sonner';
import { ThemeProvider } from "next-themes";
import { ThemeToggle } from './components/ThemeToggle'; // <-- импортируем

function App() {
  return (
    <ThemeProvider attribute="class" defaultTheme="system" enableSystem>
      <BrowserRouter>
        <div className="min-h-screen bg-background">
          <nav className="border-b">
            <div className="container mx-auto px-4">
              <div className="flex h-16 items-center justify-between">
                <div className="flex items-center space-x-6">
                  <h1 className="text-xl font-bold">Trivy Scanner</h1>
                  <div className="flex space-x-4">
                    <Link to="/quick-scan" className="text-muted-foreground hover:text-foreground px-3 py-2 text-sm font-medium transition-colors">
                      Quick Scan
                    </Link>
                    <Link to="/configs" className="text-muted-foreground hover:text-foreground px-3 py-2 text-sm font-medium transition-colors">
                      Configurations
                    </Link>
                    <Link to="/jobs" className="text-muted-foreground hover:text-foreground px-3 py-2 text-sm font-medium transition-colors">
                      Jobs
                    </Link>
                  </div>
                </div>
                <div className="flex items-center space-x-2">
                  <ThemeToggle /> {/* <-- добавляем кнопку */}
                </div>
              </div>
            </div>
          </nav>

          <main className="container mx-auto px-4 py-8">
            <Routes>
              <Route path="/" element={<Navigate to="/quick-scan" replace />} />
              <Route path="/quick-scan" element={<QuickScanPage />} />
              <Route path="/configs" element={<ConfigsPage />} />
              <Route path="/jobs" element={<JobsPage />} />
              <Route path="/jobs/:id" element={<JobDetailPage />} />
            </Routes>
          </main>
        </div>
        <Toaster />
      </BrowserRouter>
    </ThemeProvider>
  );
}

export default App;