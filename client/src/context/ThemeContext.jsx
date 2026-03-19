import React, { createContext, useContext, useState, useEffect } from 'react';

const ThemeContext = createContext(null);

const THEMES = {
  dark: { label: 'Analyst Mode', icon: 'dark_mode', description: 'Dark cybersecurity theme' },
  light: { label: 'Report Mode', icon: 'light_mode', description: 'Light professional theme' },
  soc: { label: 'SOC Mode', icon: 'monitor', description: 'High contrast terminal theme' },
};

export const ThemeProvider = ({ children, initialTheme = 'dark' }) => {
  const [theme, setTheme] = useState(() => {
    return localStorage.getItem('hs_theme') || initialTheme;
  });

  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme);
    localStorage.setItem('hs_theme', theme);
  }, [theme]);

  const cycleTheme = () => {
    const order = ['dark', 'light', 'soc'];
    const next = order[(order.indexOf(theme) + 1) % order.length];
    setTheme(next);
  };

  return (
    <ThemeContext.Provider value={{ theme, setTheme, cycleTheme, themes: THEMES }}>
      {children}
    </ThemeContext.Provider>
  );
};

export const useTheme = () => {
  const ctx = useContext(ThemeContext);
  if (!ctx) throw new Error('useTheme must be used within ThemeProvider');
  return ctx;
};
