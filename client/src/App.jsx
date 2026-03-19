import React from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { AuthProvider, useAuth } from './context/AuthContext';
import { ThemeProvider } from './context/ThemeContext';
import { ToastProvider } from './context/ToastContext';
import AppLayout from './components/layout/AppLayout';
import Dashboard from './pages/Dashboard/Dashboard';
import Scanner from './pages/Scanner/Scanner';
import Analysis from './pages/Analysis/Analysis';
import History from './pages/History/History';
import Settings from './pages/Settings/Settings';
import Login from './pages/Auth/Login';
import Register from './pages/Auth/Register';
import ToastContainer from './components/ui/ToastContainer';

/* ── Protected route wrapper ── */
const ProtectedRoute = ({ children }) => {
  const { user, loading } = useAuth();

  if (loading) {
    return (
      <div style={{
        display: 'flex', alignItems: 'center', justifyContent: 'center',
        height: '100vh', background: 'var(--bg-base)', flexDirection: 'column', gap: 16,
      }}>
        <span
          className="material-symbols-rounded"
          style={{ fontSize: 48, color: 'var(--accent-blue)', display: 'block',
            animation: 'spinLoader 1s linear infinite' }}
        >
          radar
        </span>
        <p style={{ fontFamily: 'var(--font-body)', color: 'var(--text-muted)', fontSize: 14 }}>
          Initialising HoneyScan…
        </p>
      </div>
    );
  }

  return user ? children : <Navigate to="/login" replace />;
};

/* ── Route tree ── */
const AppRoutes = () => {
  const { user } = useAuth();

  return (
    <Routes>
      {/* Auth pages — redirect to dashboard if already logged in */}
      <Route
        path="/login"
        element={user ? <Navigate to="/dashboard" replace /> : <Login />}
      />
      <Route
        path="/register"
        element={user ? <Navigate to="/dashboard" replace /> : <Register />}
      />

      {/* Protected app shell */}
      <Route
        path="/"
        element={
          <ProtectedRoute>
            <AppLayout />
          </ProtectedRoute>
        }
      >
        <Route index element={<Navigate to="/dashboard" replace />} />
        <Route path="dashboard"           element={<Dashboard />} />
        <Route path="scanner"             element={<Scanner />} />
        <Route path="analysis/:scanId"    element={<Analysis />} />
        <Route path="history"             element={<History />} />
        <Route path="settings"            element={<Settings />} />
      </Route>

      {/* Catch-all */}
      <Route path="*" element={<Navigate to="/dashboard" replace />} />
    </Routes>
  );
};

/* ── Root App ── */
export default function App() {
  return (
    <ThemeProvider>
      <AuthProvider>
        <ToastProvider>
          <BrowserRouter>
            <AppRoutes />
            <ToastContainer />
          </BrowserRouter>
        </ToastProvider>
      </AuthProvider>
    </ThemeProvider>
  );
}
