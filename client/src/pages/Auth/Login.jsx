import React, { useMemo, useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { useAuth } from '../../context/AuthContext';
import { useToast } from '../../context/ToastContext';
import styles from './Auth.module.scss';

function AuthLayout({ children }) {
  return (
    <div className={styles.layout}>
      <div className={styles.mesh} aria-hidden="true" />
      <div className={styles.brand}>
        <span className={`material-symbols-rounded ${styles.brandIcon}`}>radar</span>
        <div>
          <h1 className={styles.brandName}>HoneyScan</h1>
          <p className={styles.brandTagline}>Client-side honeypot threat detection</p>
        </div>
      </div>
      <div className={styles.card}>{children}</div>
      <div className={styles.footer}>
        <p>HoneyScan - Built for cybersecurity research. Handle responsibly.</p>
      </div>
    </div>
  );
}

function AuthField({ label, type, value, onChange, icon, error, autoComplete }) {
  const [show, setShow] = useState(false);
  const isPassword = type === 'password';

  return (
    <div className={styles.field}>
      <label className={styles.fieldLabel}>{label}</label>
      <div className={`${styles.inputWrap} ${error ? styles.inputWrapError : ''}`}>
        <span className={`material-symbols-rounded ${styles.fieldIcon}`}>{icon}</span>
        <input
          type={isPassword && show ? 'text' : type}
          className={styles.input}
          value={value}
          onChange={(e) => onChange(e.target.value)}
          autoComplete={autoComplete}
          aria-invalid={Boolean(error)}
        />
        {isPassword && (
          <button type="button" className={styles.toggleEye} onClick={() => setShow((s) => !s)}>
            <span className="material-symbols-rounded">{show ? 'visibility_off' : 'visibility'}</span>
          </button>
        )}
      </div>
      {error ? <p className={styles.errorText}>{error}</p> : null}
    </div>
  );
}

function validateEmail(email) {
  if (!email.trim()) return 'Email is required.';
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return 'Enter a valid email address.';
  return '';
}

function validatePassword(password, minLength = 8) {
  if (!password) return 'Password is required.';
  if (password.length < minLength) return `Password must be at least ${minLength} characters.`;
  return '';
}

function validateUsername(username) {
  if (!username.trim()) return 'Username is required.';
  if (username.trim().length < 3) return 'Username must be at least 3 characters.';
  if (!/^[a-zA-Z0-9_.-]+$/.test(username.trim())) return 'Use letters, numbers, dot, underscore, or dash only.';
  return '';
}

export default function Login() {
  const navigate = useNavigate();
  const { login } = useAuth();
  const { toast } = useToast();
  const [form, setForm] = useState({ email: '', password: '' });
  const [errors, setErrors] = useState({});
  const [loading, setLoading] = useState(false);

  const canSubmit = useMemo(() => form.email.trim() && form.password, [form]);

  const handleSubmit = async (e) => {
    e.preventDefault();

    const nextErrors = {
      email: validateEmail(form.email),
      password: validatePassword(form.password),
    };

    setErrors(nextErrors);
    if (nextErrors.email || nextErrors.password) {
      toast.warn('Please fix the highlighted login fields.', 3500);
      return;
    }

    setLoading(true);
    try {
      await login(form.email.trim(), form.password);
      toast.success('Welcome back.', 2500);
      navigate('/dashboard');
    } catch (err) {
      toast.error(err.response?.data?.error || 'Login failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <AuthLayout>
      <form className={styles.form} onSubmit={handleSubmit} noValidate>
        <h1 className={styles.formTitle}>Sign In</h1>
        <p className={styles.formSub}>Access your analyst dashboard</p>
        <AuthField
          label="Email"
          type="email"
          value={form.email}
          onChange={(v) => {
            setForm((f) => ({ ...f, email: v }));
            if (errors.email) setErrors((prev) => ({ ...prev, email: validateEmail(v) }));
          }}
          icon="email"
          autoComplete="email"
          error={errors.email}
        />
        <AuthField
          label="Password"
          type="password"
          value={form.password}
          onChange={(v) => {
            setForm((f) => ({ ...f, password: v }));
            if (errors.password) setErrors((prev) => ({ ...prev, password: validatePassword(v) }));
          }}
          icon="lock"
          autoComplete="current-password"
          error={errors.password}
        />
        <button type="submit" className={styles.submitBtn} disabled={loading || !canSubmit}>
          {loading
            ? <span className="material-symbols-rounded" style={{ animation: 'spinLoader 0.8s linear infinite' }}>progress_activity</span>
            : <span className="material-symbols-rounded">login</span>}
          {loading ? 'Authenticating...' : 'Sign In'}
        </button>
        <p className={styles.switchLink}>
          No account? <Link to="/register">Register</Link>
        </p>
      </form>
    </AuthLayout>
  );
}

export function Register() {
  const navigate = useNavigate();
  const { register } = useAuth();
  const { toast } = useToast();
  const [form, setForm] = useState({ username: '', email: '', password: '' });
  const [errors, setErrors] = useState({});
  const [loading, setLoading] = useState(false);

  const canSubmit = useMemo(
    () => form.username.trim() && form.email.trim() && form.password,
    [form]
  );

  const handleSubmit = async (e) => {
    e.preventDefault();

    const nextErrors = {
      username: validateUsername(form.username),
      email: validateEmail(form.email),
      password: validatePassword(form.password),
    };

    setErrors(nextErrors);
    if (nextErrors.username || nextErrors.email || nextErrors.password) {
      toast.warn('Please fix the highlighted registration fields.', 3500);
      return;
    }

    setLoading(true);
    try {
      await register(form.username.trim(), form.email.trim(), form.password);
      toast.success('Account created successfully.', 2500);
      navigate('/dashboard');
    } catch (err) {
      toast.error(err.response?.data?.error || 'Registration failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <AuthLayout>
      <form className={styles.form} onSubmit={handleSubmit} noValidate>
        <h1 className={styles.formTitle}>Create Account</h1>
        <p className={styles.formSub}>Join the HoneyScan analyst platform</p>
        <AuthField
          label="Username"
          type="text"
          value={form.username}
          onChange={(v) => {
            setForm((f) => ({ ...f, username: v }));
            if (errors.username) setErrors((prev) => ({ ...prev, username: validateUsername(v) }));
          }}
          icon="person"
          autoComplete="username"
          error={errors.username}
        />
        <AuthField
          label="Email"
          type="email"
          value={form.email}
          onChange={(v) => {
            setForm((f) => ({ ...f, email: v }));
            if (errors.email) setErrors((prev) => ({ ...prev, email: validateEmail(v) }));
          }}
          icon="email"
          autoComplete="email"
          error={errors.email}
        />
        <AuthField
          label="Password (min. 8 chars)"
          type="password"
          value={form.password}
          onChange={(v) => {
            setForm((f) => ({ ...f, password: v }));
            if (errors.password) setErrors((prev) => ({ ...prev, password: validatePassword(v) }));
          }}
          icon="lock"
          autoComplete="new-password"
          error={errors.password}
        />
        <button type="submit" className={styles.submitBtn} disabled={loading || !canSubmit}>
          {loading
            ? <span className="material-symbols-rounded" style={{ animation: 'spinLoader 0.8s linear infinite' }}>progress_activity</span>
            : <span className="material-symbols-rounded">person_add</span>}
          {loading ? 'Creating account...' : 'Create Account'}
        </button>
        <p className={styles.switchLink}>
          Already have an account? <Link to="/login">Sign in</Link>
        </p>
      </form>
    </AuthLayout>
  );
}
