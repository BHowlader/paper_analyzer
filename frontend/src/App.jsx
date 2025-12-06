import React, { useState, useEffect } from 'react';
import { BrowserRouter as Router, Routes, Route, Link, useNavigate, useSearchParams } from 'react-router-dom';
// eslint-disable-next-line no-unused-vars
import { motion, AnimatePresence } from 'framer-motion';
import { Upload, FileText, MessageSquare, LogOut, Menu, X, Check, Zap, Shield, Star, ChevronRight, Loader2, History, Plus, GripVertical } from 'lucide-react';
import axios from 'axios';
import clsx from 'clsx';
import { twMerge } from 'tailwind-merge';

// --- Utility ---
function cn(...inputs) {
  return twMerge(clsx(inputs));
}

// --- API ---
const API_URL = import.meta.env.VITE_API_URL || '/api/v1';

const api = axios.create({
  baseURL: API_URL,
});

api.interceptors.request.use((config) => {
  const token = localStorage.getItem('token');
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response && error.response.status === 401) {
      localStorage.removeItem('token');
      localStorage.removeItem('userEmail');
      localStorage.removeItem('userPicture');
      window.location.href = '/login';
    }
    return Promise.reject(error);
  }
);

// --- Components ---

const Button = ({ className, variant = 'primary', size = 'md', isLoading, children, ...props }) => {
  const variants = {
    primary: 'bg-indigo-600 text-white hover:bg-indigo-700 shadow-lg shadow-indigo-500/25 border-none',
    secondary: 'bg-white text-slate-700 border border-slate-200 hover:bg-slate-50',
    ghost: 'bg-transparent text-slate-600 hover:text-slate-900 hover:bg-slate-100',
    outline: 'border border-indigo-200 text-indigo-600 hover:bg-indigo-50'
  };

  const sizes = {
    sm: 'px-3 py-1.5 text-sm',
    md: 'px-5 py-2.5 text-sm',
    lg: 'px-6 py-3 text-base'
  };

  return (
    <button
      className={cn(
        'inline-flex items-center justify-center rounded-xl font-medium transition-all duration-200 disabled:opacity-50 disabled:cursor-not-allowed active:scale-95',
        variants[variant],
        sizes[size],
        className
      )}
      disabled={isLoading}
      {...props}
    >
      {isLoading && <Loader2 className="w-4 h-4 mr-2 animate-spin" />}
      {children}
    </button>
  );
};

const Input = ({ className, ...props }) => (
  <input
    className={cn(
      "flex h-11 w-full rounded-xl border border-white/10 bg-slate-800/50 px-3 py-2 text-sm ring-offset-slate-950 file:border-0 file:bg-transparent file:text-sm file:font-medium placeholder:text-slate-500 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-indigo-500 focus-visible:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50 transition-all duration-200 text-white",
      className
    )}
    {...props}
  />
);

const Card = ({ className, children }) => (
  <div className={cn("rounded-2xl border border-white/10 bg-slate-900/50 backdrop-blur-xl shadow-2xl transition-all duration-300 hover:border-white/20", className)}>
    {children}
  </div>
);

// --- Pages ---

const Pricing = () => {
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();
  const token = localStorage.getItem('token');

  const handleUpgrade = async () => {
    if (!token) {
      navigate('/login');
      return;
    }

    setLoading(true);
    try {
      const res = await api.post('/payment/create-checkout-session');
      if (res.data.url) {
        window.location.href = res.data.url;
      } else {
        alert('Something went wrong, please try again later.');
      }
    } catch (err) {
      console.error(err);
      if (err.response?.status === 401) {
        navigate('/login');
      } else {
        alert('Failed to start payment: ' + (err.response?.data?.detail || err.message));
      }
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-slate-50 relative overflow-hidden font-sans text-slate-700">
      {/* Background Decoration */}
      <div className="absolute inset-0 -z-10 overflow-hidden bg-slate-50">
        <div className="absolute inset-0 bg-[linear-gradient(to_right,#e2e8f0_1px,transparent_1px),linear-gradient(to_bottom,#e2e8f0_1px,transparent_1px)] bg-[size:14px_24px] [mask-image:radial-gradient(ellipse_60%_50%_at_50%_0%,#000_70%,transparent_100%)]"></div>
        <div className="absolute top-0 left-1/2 -translate-x-1/2 w-[1000px] h-[500px] bg-indigo-500/10 rounded-full blur-[100px]" />
      </div>

      <nav className="bg-white/80 backdrop-blur-md border-b border-slate-200 sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between h-16">
            <div className="flex">
              <Link to="/" className="flex-shrink-0 flex items-center gap-2">
                <div className="p-1.5 bg-indigo-600 rounded-lg shadow-sm">
                  <FileText className="w-5 h-5 text-white" />
                </div>
                <span className="font-bold text-xl text-slate-900">Paper Analyzer</span>
              </Link>
            </div>
            <div className="flex items-center gap-4">
              {token ? (
                <Link to="/dashboard"><Button variant="ghost">Dashboard</Button></Link>
              ) : (
                <>
                  <Link to="/login"><Button variant="ghost">Sign in</Button></Link>
                  <Link to="/signup"><Button>Get Started</Button></Link>
                </>
              )}
            </div>
          </div>
        </div>
      </nav>
      <div className="max-w-7xl mx-auto px-4 py-20">
        <div className="text-center mb-16">
          <h2 className="text-4xl font-bold text-slate-900 mb-4">Simple, Transparent Pricing</h2>
          <p className="text-xl text-slate-600">Choose the plan that fits your research needs</p>
        </div>

        <div className="grid md:grid-cols-2 gap-8 max-w-4xl mx-auto">
          {/* Free Plan */}
          <Card className="p-8 border-slate-200 bg-white hover:border-indigo-300 transition-colors">
            <h3 className="text-2xl font-bold text-slate-900 mb-2">Free</h3>
            <div className="mb-6">
              <span className="text-4xl font-bold text-slate-900">$0</span>
              <span className="text-slate-500">/month</span>
            </div>
            <ul className="space-y-4 mb-8">
              <li className="flex items-center text-slate-700">
                <Check className="w-5 h-5 text-emerald-600 mr-3" />
                50 Questions per day
              </li>
              <li className="flex items-center text-slate-700">
                <Check className="w-5 h-5 text-emerald-600 mr-3" />
                5 Uploads per day
              </li>
              <li className="flex items-center text-slate-700">
                <Check className="w-5 h-5 text-emerald-600 mr-3" />
                Basic PDF Analysis
              </li>
              <li className="flex items-center text-slate-700">
                <Check className="w-5 h-5 text-emerald-600 mr-3" />
                Chat with Paper history
              </li>
            </ul>
            <Link to={token ? "/dashboard" : "/signup"}>
              <Button variant="secondary" className="w-full bg-white border-slate-200 text-slate-700 hover:bg-slate-50">
                {token ? "Go to Dashboard" : "Sign Up Free"}
              </Button>
            </Link>
          </Card>

          {/* Pro Plan */}
          <Card className="p-8 border-indigo-500 bg-indigo-50 relative overflow-hidden ring-2 ring-indigo-500 ring-offset-2 ring-offset-slate-50">
            <div className="absolute top-0 right-0 bg-indigo-600 text-white px-3 py-1 text-xs font-bold uppercase rounded-bl-lg">
              Popular
            </div>
            <h3 className="text-2xl font-bold text-slate-900 mb-2">Pro</h3>
            <div className="mb-6">
              <span className="text-4xl font-bold text-slate-900">$10</span>
              <span className="text-slate-600">/month</span>
            </div>
            <ul className="space-y-4 mb-8">
              <li className="flex items-center text-indigo-700">
                <Check className="w-5 h-5 text-emerald-600 mr-3" />
                Unlimited Questions
              </li>
              <li className="flex items-center text-indigo-700">
                <Check className="w-5 h-5 text-emerald-600 mr-3" />
                Unlimited Uploads
              </li>
              <li className="flex items-center text-indigo-700">
                <Check className="w-5 h-5 text-emerald-600 mr-3" />
                Advanced AI Models (Gemini 1.5)
              </li>
              <li className="flex items-center text-indigo-700">
                <Check className="w-5 h-5 text-emerald-600 mr-3" />
                Priority Support
              </li>
              <li className="flex items-center text-indigo-700">
                <Check className="w-5 h-5 text-emerald-600 mr-3" />
                Early Access to new features
              </li>
            </ul>
            <Button
              className="w-full bg-indigo-600 hover:bg-indigo-500"
              onClick={handleUpgrade}
              isLoading={loading}
            >
              Upgrade to Pro
            </Button>
          </Card>
        </div>
      </div>
    </div>
  );
};

const Landing = () => {
  return (
    <div className="min-h-screen bg-slate-50 selection:bg-indigo-200 selection:text-indigo-800">
      {/* Navbar */}
      <nav className="fixed top-0 w-full z-50 bg-white/80 backdrop-blur-md border-b border-slate-200">
        <div className="container mx-auto px-4 h-16 flex items-center justify-between">
          <Link to="/" className="flex items-center gap-2 text-indigo-600 hover:opacity-80 transition-opacity">
            <div className="p-2 bg-indigo-500/10 rounded-lg border border-indigo-500/20">
              <FileText className="w-5 h-5 text-indigo-600" />
            </div>
            <span className="text-lg font-bold tracking-tight text-slate-900">PaperAnalyzer</span>
          </Link>
          <div className="flex items-center gap-4">
            {localStorage.getItem('token') ? (
              <Link to="/dashboard">
                <Button size="sm" className="rounded-full px-6 bg-indigo-600 text-white hover:bg-indigo-700 border-none shadow-lg shadow-indigo-500/20">Dashboard</Button>
              </Link>
            ) : (
              <>
                <Link to="/login" className="text-sm font-medium text-slate-600 hover:text-slate-900 transition-colors">Sign in</Link>
                <Link to="/signup">
                  <Button size="sm" className="rounded-full px-6 bg-indigo-600 text-white hover:bg-indigo-700 border-none">Get Started</Button>
                </Link>
              </>
            )}
          </div>
        </div>
      </nav>

      {/* Hero Section */}
      <section className="relative pt-32 pb-20 overflow-hidden">
        {/* Background Elements */}
        <div className="absolute inset-0 -z-10 overflow-hidden bg-slate-50">
          <div className="absolute inset-0 bg-[linear-gradient(to_right,#e2e8f0_1px,transparent_1px),linear-gradient(to_bottom,#e2e8f0_1px,transparent_1px)] bg-[size:14px_24px] [mask-image:radial-gradient(ellipse_60%_50%_at_50%_0%,#000_70%,transparent_100%)]"></div>
          <motion.div
            animate={{
              scale: [1, 1.2, 1],
              opacity: [0.3, 0.5, 0.3],
            }}
            transition={{ duration: 8, repeat: Infinity, ease: "easeInOut" }}
            className="absolute top-0 left-1/2 -translate-x-1/2 w-[1000px] h-[500px] bg-indigo-500/10 rounded-full blur-[100px] mix-blend-screen"
          />
          <div className="absolute top-1/2 left-0 w-[800px] h-[600px] bg-violet-500/5 rounded-full blur-[100px] opacity-40 mix-blend-screen" />
          <div className="absolute bottom-0 right-0 w-[600px] h-[600px] bg-blue-500/5 rounded-full blur-[100px] opacity-40 mix-blend-screen" />
        </div>

        <div className="container mx-auto px-4 relative z-10">
          <div className="max-w-5xl mx-auto text-center">
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.5 }}
            >
              <div className="inline-flex items-center gap-2 py-1 px-3 rounded-full bg-indigo-50 border border-indigo-200 shadow-sm mb-8 hover:border-indigo-300 transition-colors cursor-default backdrop-blur-sm">
                <span className="flex h-2 w-2 rounded-full bg-emerald-500 shadow-[0_0_10px_rgba(52,211,153,0.5)]"></span>
                <span className="text-sm font-medium text-indigo-600">v2.0 is now live</span>
              </div>

              <h1 className="text-5xl md:text-7xl font-bold tracking-tight text-slate-900 mb-8 leading-[1.1]">
                Research Papers, <br />
                <span className="text-transparent bg-clip-text bg-gradient-to-r from-indigo-600 via-violet-600 to-blue-600">Simplified by AI.</span>
              </h1>

              <p className="text-xl text-slate-600 mb-10 max-w-2xl mx-auto leading-relaxed">
                Stop spending hours reading dense PDFs. Upload your paper and get instant summaries, key findings, and answers to your questions.
              </p>

              <div className="flex flex-col sm:flex-row items-center justify-center gap-4 mb-16">
                <Link to={localStorage.getItem('token') ? "/dashboard" : "/signup"}>
                  <Button size="lg" className="w-full sm:w-auto text-lg h-14 px-8 rounded-full bg-indigo-600 hover:bg-indigo-700 text-white border-none shadow-xl shadow-indigo-500/20 transition-all duration-200 hover:-translate-y-1">
                    {localStorage.getItem('token') ? "Go to Dashboard" : "Analyze Paper for Free"} <ChevronRight className="ml-2 w-5 h-5" />
                  </Button>
                </Link>
                <Link to="/pricing">
                  <Button variant="secondary" size="lg" className="w-full sm:w-auto text-lg h-14 px-8 rounded-full bg-white border-slate-200 text-slate-700 hover:bg-slate-50 transition-all duration-200 shadow-sm">
                    View Pricing
                  </Button>
                </Link>
              </div>

              {/* Stats / Social Proof */}
              <div className="flex justify-center gap-8 text-slate-500 mb-20">
                <div className="flex items-center gap-2"><Star className="w-4 h-4" /> <span>Trusted by Researchers</span></div>
                <div className="flex items-center gap-2"><Shield className="w-4 h-4" /> <span>Secure & Private</span></div>
              </div>
            </motion.div>
          </div>
        </div>

        {/* Abstract UI Demo */}
        <motion.div
          initial={{ opacity: 0, y: 40 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.2, duration: 0.8 }}
          className="container mx-auto px-4"
        >
          <div className="relative rounded-2xl overflow-hidden shadow-2xl shadow-indigo-200/30 border border-slate-200 bg-white backdrop-blur-xl max-w-6xl mx-auto ring-1 ring-black/5">
            <div className="absolute top-0 left-0 right-0 h-11 bg-slate-100 border-b border-slate-200 flex items-center px-4 gap-2">
              <div className="flex gap-1.5">
                <div className="w-3 h-3 rounded-full bg-red-400 border border-red-500/20"></div>
                <div className="w-3 h-3 rounded-full bg-amber-400 border border-amber-500/20"></div>
                <div className="w-3 h-3 rounded-full bg-emerald-400 border border-emerald-500/20"></div>
              </div>
              <div className="mx-auto text-xs font-medium text-slate-500 bg-white px-3 py-1 rounded-md border border-slate-200 shadow-sm">paper_analysis_demo.pdf</div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-12 gap-0 h-[600px] bg-slate-50 mt-11">
              {/* Sidebar */}
              <div className="hidden md:block col-span-3 border-r border-slate-200 bg-slate-100 p-4 space-y-4">
                <div className="h-4 w-24 bg-slate-200 rounded animate-pulse"></div>
                <div className="space-y-2">
                  <div className="h-8 w-full bg-indigo-100 text-indigo-700 border border-indigo-200 rounded-lg flex items-center px-3 text-sm font-medium">Abstract</div>
                  <div className="h-8 w-full hover:bg-slate-100 text-slate-600 rounded-lg flex items-center px-3 text-sm font-medium transition-colors">Methodology</div>
                  <div className="h-8 w-full hover:bg-slate-100 text-slate-600 rounded-lg flex items-center px-3 text-sm font-medium transition-colors">Results</div>
                  <div className="h-8 w-full hover:bg-slate-100 text-slate-600 rounded-lg flex items-center px-3 text-sm font-medium transition-colors">Conclusion</div>
                </div>
              </div>

              {/* Main Content */}
              <div className="col-span-12 md:col-span-5 p-8 overflow-hidden relative">
                <div className="absolute inset-0 bg-gradient-to-b from-transparent via-transparent to-slate-50 z-10"></div>
                <div className="space-y-4">
                  <div className="h-8 w-3/4 bg-slate-200 rounded-lg mb-6"></div>
                  <div className="space-y-2">
                    <div className="h-4 w-full bg-slate-200 rounded"></div>
                    <div className="h-4 w-full bg-slate-200 rounded"></div>
                    <div className="h-4 w-5/6 bg-slate-200 rounded"></div>
                  </div>
                  <div className="space-y-2 pt-4">
                    <div className="h-4 w-full bg-slate-200 rounded"></div>
                    <div className="h-4 w-full bg-slate-200 rounded"></div>
                    <div className="h-4 w-4/6 bg-slate-200 rounded"></div>
                  </div>
                  <div className="p-4 bg-indigo-50/50 rounded-xl border border-indigo-200 mt-6">
                    <div className="h-5 w-32 bg-indigo-100 rounded mb-2"></div>
                    <div className="h-4 w-full bg-indigo-50 rounded"></div>
                  </div>
                </div>
              </div>

              {/* Chat Interface */}
              <div className="hidden md:flex col-span-4 border-l border-slate-200 flex-col bg-slate-100">
                <div className="flex-1 p-4 space-y-4">
                  <div className="flex justify-end">
                    <div className="bg-indigo-600 text-white px-4 py-2 rounded-2xl rounded-br-none text-sm max-w-[85%] shadow-lg shadow-indigo-500/20">
                      What is the main contribution of this paper?
                    </div>
                  </div>
                  <div className="flex justify-start">
                    <div className="bg-white text-slate-700 px-4 py-2 rounded-2xl rounded-bl-none text-sm max-w-[85%] border border-slate-200">
                      The paper introduces a novel transformer architecture that reduces computational cost by 40% while maintaining accuracy.
                    </div>
                  </div>
                </div>
                <div className="p-4 border-t border-slate-200">
                  <div className="h-10 bg-white border border-slate-200 rounded-xl w-full"></div>
                </div>
              </div>
            </div>
          </div>
        </motion.div>
      </section>
    </div>
  );
};

const Login = () => {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();

  const handleLogin = async (e) => {
    e.preventDefault();
    setLoading(true);
    try {
      const formData = new URLSearchParams();
      formData.append('username', email);
      formData.append('password', password);

      const res = await api.post('/auth/token', formData);
      localStorage.setItem('token', res.data.access_token);
      localStorage.setItem('userEmail', res.data.user_email);
      if (res.data.user_picture) localStorage.setItem('userPicture', res.data.user_picture);
      navigate('/dashboard');
    } catch (err) {
      alert('Login failed: ' + (err.response?.data?.detail || err.message));
    } finally {
      setLoading(false);
    }
  };

  const handleGoogleLogin = async () => {
    try {
      const res = await api.get('/auth/google/login');
      window.location.href = res.data.url;
    } catch (err) {
      console.error(err);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-slate-50 px-4 relative overflow-hidden">
      {/* Background Elements */}
      <div className="absolute inset-0 -z-10 overflow-hidden">
        <div className="absolute top-0 left-1/2 -translate-x-1/2 w-[1000px] h-[500px] bg-indigo-500/10 rounded-full blur-[100px]" />
      </div>

      <Card className="w-full max-w-md p-8 bg-white border-slate-200 shadow-xl">
        <div className="flex justify-center mb-6">
          <Link to="/" className="flex items-center text-indigo-600 hover:text-indigo-700 transition-colors">
            <FileText className="w-8 h-8 mr-2" />
            <span className="text-xl font-bold tracking-tight text-slate-900">PaperAnalyzer</span>
          </Link>
        </div>
        <div className="text-center mb-8">
          <h2 className="text-2xl font-bold text-slate-900">Welcome back</h2>
          <p className="text-slate-600 mt-2">Enter your details to access your account</p>
        </div>

        <form onSubmit={handleLogin} className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-slate-700 mb-1">Email</label>
            <Input type="email" value={email} onChange={(e) => setEmail(e.target.value)} required className="bg-white border-slate-200 text-slate-900 placeholder:text-slate-400 focus:border-indigo-500 focus:ring-indigo-500/20" />
          </div>
          <div>
            <label className="block text-sm font-medium text-slate-700 mb-1">Password</label>
            <Input type="password" value={password} onChange={(e) => setPassword(e.target.value)} required className="bg-white border-slate-200 text-slate-900 placeholder:text-slate-400 focus:border-indigo-500 focus:ring-indigo-500/20" />
          </div>
          <Button type="submit" className="w-full bg-indigo-600 hover:bg-indigo-500 text-white border-none" isLoading={loading}>Sign In</Button>
        </form>

        <div className="mt-6">
          <div className="relative">
            <div className="absolute inset-0 flex items-center"><div className="w-full border-t border-slate-200"></div></div>
            <div className="relative flex justify-center text-sm"><span className="px-2 bg-white text-slate-500">Or continue with</span></div>
          </div>
          <Button variant="secondary" className="w-full mt-6 bg-white border-slate-200 text-slate-700 hover:bg-slate-50" onClick={handleGoogleLogin}>
            <svg className="h-5 w-5 mr-2" viewBox="0 0 24 24" fill="currentColor"><path d="M12.545,10.239v3.821h5.445c-0.712,2.315-2.647,3.972-5.445,3.972c-3.332,0-6.033-2.701-6.033-6.032s2.701-6.032,6.033-6.032c1.498,0,2.866,0.549,3.921,1.453l2.814-2.814C17.503,2.988,15.139,2,12.545,2C7.021,2,2.543,6.477,2.543,12s4.478,10,10.002,10c8.396,0,10.249-7.85,9.426-11.748L12.545,10.239z" /></svg>
            Google
          </Button>
        </div>

        <p className="mt-6 text-center text-sm text-slate-500">
          Don't have an account? <Link to="/signup" className="font-medium text-indigo-600 hover:text-indigo-700">Sign up</Link>
        </p>
      </Card>
    </div>
  );
};

const Signup = () => {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();

  const handleSignup = async (e) => {
    e.preventDefault();
    setLoading(true);
    try {
      await api.post('/auth/signup', { email, password });
      // Auto login
      const formData = new URLSearchParams();
      formData.append('username', email);
      formData.append('password', password);
      const res = await api.post('/auth/token', formData);
      localStorage.setItem('token', res.data.access_token);
      navigate('/dashboard');
    } catch (err) {
      alert('Signup failed: ' + (err.response?.data?.detail || err.message));
    } finally {
      setLoading(false);
    }
  };

  const handleGoogleLogin = async () => {
    try {
      const res = await api.get('/auth/google/login');
      window.location.href = res.data.url;
    } catch (err) {
      console.error(err);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-slate-50 px-4 relative overflow-hidden">
      {/* Background Elements */}
      <div className="absolute inset-0 -z-10 overflow-hidden">
        <div className="absolute top-0 left-1/2 -translate-x-1/2 w-[1000px] h-[500px] bg-indigo-500/10 rounded-full blur-[100px] opacity-30 mix-blend-screen animate-pulse" />
      </div>

      <Card className="w-full max-w-md p-8 bg-white border-slate-200 backdrop-blur-xl shadow-xl shadow-indigo-100/50">
        <div className="flex justify-center mb-6">
          <Link to="/" className="flex items-center text-indigo-600 hover:text-indigo-700 transition-colors">
            <FileText className="w-8 h-8 mr-2" />
            <span className="text-xl font-bold tracking-tight text-slate-900">PaperAnalyzer</span>
          </Link>
        </div>
        <div className="text-center mb-8">
          <h2 className="text-2xl font-bold text-slate-900">Create an account</h2>
          <p className="text-slate-600 mt-2">Start analyzing papers in seconds</p>
        </div>

        <form onSubmit={handleSignup} className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-slate-700 mb-1">Email</label>
            <Input type="email" value={email} onChange={(e) => setEmail(e.target.value)} required className="bg-white border-slate-200 text-slate-900 placeholder:text-slate-400 focus:border-indigo-500 focus:ring-indigo-500/20" />
          </div>
          <div>
            <label className="block text-sm font-medium text-slate-700 mb-1">Password</label>
            <Input type="password" value={password} onChange={(e) => setPassword(e.target.value)} required className="bg-white border-slate-200 text-slate-900 placeholder:text-slate-400 focus:border-indigo-500 focus:ring-indigo-500/20" />
          </div>
          <Button type="submit" className="w-full bg-indigo-600 hover:bg-indigo-500 text-white border-none" isLoading={loading}>Sign Up</Button>
        </form>

        <div className="mt-6">
          <div className="relative">
            <div className="absolute inset-0 flex items-center"><div className="w-full border-t border-slate-200"></div></div>
            <div className="relative flex justify-center text-sm"><span className="px-2 bg-white text-slate-500">Or continue with</span></div>
          </div>
          <Button variant="secondary" className="w-full mt-6 bg-white border-slate-200 text-slate-700 hover:bg-slate-50" onClick={handleGoogleLogin}>
            <svg className="h-5 w-5 mr-2" viewBox="0 0 24 24" fill="currentColor"><path d="M12.545,10.239v3.821h5.445c-0.712,2.315-2.647,3.972-5.445,3.972c-3.332,0-6.033-2.701-6.033-6.032s2.701-6.032,6.033-6.032c1.498,0,2.866,0.549,3.921,1.453l2.814-2.814C17.503,2.988,15.139,2,12.545,2C7.021,2,2.543,6.477,2.543,12s4.478,10,10.002,10c8.396,0,10.249-7.85,9.426-11.748L12.545,10.239z" /></svg>
            Google
          </Button>
        </div>

        <p className="mt-6 text-center text-sm text-slate-500">
          Already have an account? <Link to="/login" className="font-medium text-indigo-600 hover:text-indigo-700">Sign in</Link>
        </p>
      </Card>
    </div>
  );
};

const Dashboard = () => {
  const [analyzing, setAnalyzing] = useState(false);
  const [result, setResult] = useState(null);
  const [chatInput, setChatInput] = useState('');
  const [messages, setMessages] = useState([]);
  const [chatLoading, setChatLoading] = useState(false);
  const [history, setHistory] = useState([]);
  const [activeSection, setActiveSection] = useState('abstract');

  // -- Resizable Workspace State --
  const [leftWidth, setLeftWidth] = useState(280);
  const [rightWidth, setRightWidth] = useState(350);
  const [isResizing, setIsResizing] = useState(null); // 'left' | 'right'
  const [mobileView, setMobileView] = useState('content'); // 'nav' | 'content' | 'chat'
  const [isDesktop, setIsDesktop] = useState(window.innerWidth >= 1024);
  const [isMobileNavOpen, setIsMobileNavOpen] = useState(false);

  useEffect(() => {
    const handleResize = () => setIsDesktop(window.innerWidth >= 1024);
    window.addEventListener('resize', handleResize);
    return () => window.removeEventListener('resize', handleResize);
  }, []);

  // -- Resize Handlers --
  const startResizing = (direction) => (e) => {
    e.preventDefault();
    setIsResizing(direction);
  };

  useEffect(() => {
    const handleMouseMove = (e) => {
      if (!isResizing) return;
      if (isResizing === 'left') {
        const newWidth = Math.max(220, Math.min(e.clientX, 500));
        setLeftWidth(newWidth);
      } else {
        const newWidth = Math.max(280, Math.min(window.innerWidth - e.clientX, 600));
        setRightWidth(newWidth);
      }
    };

    const handleMouseUp = () => {
      setIsResizing(null);
      // Reset body cursor
      document.body.style.cursor = '';
    };

    if (isResizing) {
      window.addEventListener('mousemove', handleMouseMove);
      window.addEventListener('mouseup', handleMouseUp);
      document.body.style.cursor = 'col-resize';
    }
    return () => {
      window.removeEventListener('mousemove', handleMouseMove);
      window.removeEventListener('mouseup', handleMouseUp);
    };
  }, [isResizing]);

  const [usage, setUsage] = useState({ count: 0, limit: 5, plan: 'free' });
  const navigate = useNavigate();

  const [isChatOpen, setIsChatOpen] = useState(false);
  const [searchParams] = useSearchParams();

  useEffect(() => {
    if (!localStorage.getItem('token')) {
      navigate('/login');
    } else {
      if (searchParams.get('payment_success')) {
        alert("Payment successful! Welcome to Pro.");
        // Clear params to avoid popup on refresh
        navigate('/dashboard', { replace: true });
      }

      fetchHistory();
      fetchUsage();
    }
  }, [navigate, searchParams]);

  const fetchUsage = async () => {
    try {
      const res = await api.get('/analysis/usage');
      setUsage(res.data);
    } catch (err) { console.error(err); }
  };

  const fetchHistory = async () => {
    try {
      const res = await api.get('/analysis/history');
      setHistory(res.data);
    } catch (err) {
      console.error("Failed to fetch history", err);
    }
  };

  const handleHistoryClick = (item) => {
    setResult(item);
    setMessages(item.chat_history || []); // Load saved history
  };

  const handleLogout = () => {
    localStorage.removeItem('token');
    localStorage.removeItem('userEmail');
    localStorage.removeItem('userPicture');
    navigate('/');
  };

  // --- Alert State ---
  const [alertState, setAlertState] = useState({ open: false, title: '', message: '' });

  const closeAlert = () => setAlertState(prev => ({ ...prev, open: false }));

  const handleUpload = async (e) => {
    const selectedFile = e.target.files[0];
    if (!selectedFile) return;

    setAnalyzing(true);

    const formData = new FormData();
    formData.append('file', selectedFile);

    try {
      const res = await api.post('/analysis/upload', formData);
      setResult(res.data);
      setMessages([]); // Clear chat for new paper
      fetchHistory(); // Refresh history
      fetchUsage(); // Update usage after upload
    } catch (err) {
      console.error(err);
      setAlertState({
        open: true,
        title: 'Analysis Failed',
        message: err.response?.data?.detail || err.message
      });
    } finally {
      setAnalyzing(false);
    }
  };

  const handleChat = async (e) => {
    e.preventDefault();
    if (!chatInput.trim() || !result) return;

    const userMsg = { role: 'user', content: chatInput };
    setMessages(prev => [...prev, userMsg]);
    setChatInput('');
    setChatLoading(true);

    try {
      const res = await api.post('/analysis/chat', {
        analysis_id: result.id,
        question: userMsg.content,
        history: messages
      });
      setMessages(prev => [...prev, { role: 'assistant', content: res.data.answer }]);
      fetchUsage(); // Update usage after chat
    } catch {
      setMessages(prev => [...prev, { role: 'assistant', content: 'Error getting response.' }]);
    } finally {
      setChatLoading(false);
    }
  };




  return (
    <div className="flex h-screen bg-slate-50 text-slate-700 overflow-hidden font-sans relative">
      {/* Mobile Nav Toggle */}
      <button
        className="md:hidden absolute top-4 left-4 z-50 p-2 bg-white rounded-lg shadow-md border border-slate-200 text-slate-700"
        onClick={() => setIsMobileNavOpen(!isMobileNavOpen)}
      >
        <Menu className="w-5 h-5" />
      </button>

      {/* Sidebar Overlay for Mobile */}
      {isMobileNavOpen && (
        <div
          className="fixed inset-0 bg-black/50 z-30 md:hidden backdrop-blur-sm"
          onClick={() => setIsMobileNavOpen(false)}
        />
      )}

      {/* Sidebar */}
      <div className={cn(
        "w-64 bg-white border-r border-slate-200 flex flex-col z-40 shadow-sm transition-transform duration-300 absolute md:relative h-full",
        isMobileNavOpen ? "translate-x-0" : "-translate-x-full md:translate-x-0"
      )}>
        <Link to="/" className="p-4 border-b border-slate-100 flex items-center gap-2 hover:bg-slate-50 transition-colors cursor-pointer">
          <div className="p-1.5 bg-indigo-600 rounded-lg shadow-sm">
            <FileText className="w-5 h-5 text-white" />
          </div>
          <span className="font-bold text-lg text-slate-900">Paper Analyzer</span>
        </Link>

        <div className="flex-1 overflow-y-auto p-4 space-y-6">
          <div className="space-y-1">
            <Button
              variant="ghost"
              className="w-full justify-start text-indigo-600 bg-indigo-50 font-medium cursor-pointer"
              onClick={() => {
                setResult(null);
                setMessages([]);
              }}
            >
              <Plus className="w-4 h-4 mr-2" /> New Analysis
            </Button>
          </div>
          <div className="space-y-2">
            <div className="px-3 text-xs font-semibold text-slate-400 uppercase tracking-wider">History</div>
            {history.map((item) => (
              <button
                key={item.id}
                onClick={() => handleHistoryClick(item)}
                className="w-full text-left px-3 py-2 text-sm text-slate-600 hover:text-slate-900 hover:bg-slate-100 rounded-lg transition-colors truncate"
                title={item.title}
              >
                {item.title}
              </button>
            ))}
          </div>
        </div>

        <div className="p-4 border-t border-slate-100 bg-slate-50/50">
          <div className="flex items-center gap-3 mb-4">
            {localStorage.getItem('userPicture') ? (
              <img
                src={localStorage.getItem('userPicture')}
                alt="Profile"
                className="w-8 h-8 rounded-full border border-slate-200 shadow-sm"
                referrerPolicy="no-referrer"
              />
            ) : (
              <div className="w-8 h-8 rounded-full bg-indigo-100 flex items-center justify-center text-indigo-700 font-bold border border-indigo-200">
                {localStorage.getItem('userEmail')?.[0]?.toUpperCase() || 'U'}
              </div>
            )}
            <div className="flex-1 min-w-0">
              <div className="text-sm font-medium text-slate-900 truncate">{localStorage.getItem('userEmail')}</div>
              <div className="text-xs text-slate-500 capitalize">{usage.plan} Plan</div>
            </div>
          </div>
          <div className="mb-4 space-y-2">
            <div className="flex justify-between text-xs text-slate-500">
              <span>Paper Uploads</span>
              <span>{usage.count} / {usage.limit}</span>
            </div>
            <div className="w-full bg-slate-200 rounded-full h-1.5 overflow-hidden">
              <div
                className="bg-indigo-600 h-1.5 rounded-full transition-all duration-500"
                style={{ width: `${Math.min((usage.count / (usage.limit === 'Unlimited' ? 100 : usage.limit)) * 100, 100)}%` }}
              ></div>
            </div>
          </div>
          <Button variant="ghost" className="w-full justify-start text-slate-500 hover:text-red-600 hover:bg-red-50 text-sm h-8" onClick={handleLogout}>
            <LogOut className="w-4 h-4 mr-2" /> Sign out
          </Button>
        </div>
      </div>

      {result ? (
        // --- WORKSPACE VIEW (Active Analysis) ---
        <div className="h-screen flex flex-col overflow-hidden flex-1">
          {/* Workspace Header */}
          <div className="h-14 bg-white/80 border-b border-slate-200 flex items-center px-4 justify-between backdrop-blur-md shrink-0">
            <div className="flex items-center gap-3 relative z-10">
              <Link to="/dashboard" onClick={() => { setResult(null); }} className="p-2 hover:bg-slate-100 rounded-lg transition-colors shrink-0">
                <FileText className="w-5 h-5 text-indigo-600" />
              </Link>
            </div>

            <div className="absolute left-1/2 top-1/2 -translate-x-1/2 -translate-y-1/2 max-w-[400px] lg:max-w-[600px] w-full text-center px-4">
              <span className="text-sm font-medium text-slate-700 bg-slate-100/50 px-4 py-1.5 rounded-full border border-slate-200 truncate inline-block max-w-full" title={result.title}>
                {result.title}
              </span>
            </div>

            <div className="flex items-center gap-4 relative z-10">
              <div className="hidden md:flex items-center gap-3 border-r border-slate-200 pr-4">
                {localStorage.getItem('userPicture') ? (
                  <img
                    src={localStorage.getItem('userPicture')}
                    alt="Profile"
                    className="w-8 h-8 rounded-full border border-slate-200 shadow-sm"
                    referrerPolicy="no-referrer"
                  />
                ) : (
                  <div className="w-8 h-8 rounded-full bg-indigo-100 flex items-center justify-center text-indigo-700 font-bold border border-indigo-200 shadow-sm text-xs">
                    {localStorage.getItem('userEmail')?.charAt(0).toUpperCase() || 'U'}
                  </div>
                )}
                <div className="text-xs">
                  <p className="font-medium text-slate-900">{localStorage.getItem('userEmail')}</p>
                  <p className="text-[10px] text-indigo-600 font-medium cursor-pointer hover:underline" onClick={() => navigate('/pricing')}>
                    {usage.plan === 'free' ? `Free (${usage.count}/${usage.limit})` : 'Pro Plan'}
                  </p>
                </div>
              </div>
              <Button variant="ghost" size="sm" onClick={() => setResult(null)} className="text-slate-600 hover:bg-slate-100 hover:text-slate-900">Close</Button>
            </div>
          </div>

          <div className="flex-1 flex flex-col lg:flex-row overflow-hidden relative z-10">

            {/* -- Mobile Tab Navigation -- */}
            <div className="lg:hidden h-14 bg-white border-b border-slate-200 flex items-center justify-around px-2 shrink-0 z-20">
              <button onClick={() => setMobileView('nav')} className={cn("p-2 rounded-xl flex items-center gap-2 text-sm font-medium transition-colors", mobileView === 'nav' ? "text-indigo-600 bg-indigo-50" : "text-slate-600")}>
                <Menu className="w-5 h-5" /> Sections
              </button>
              <button onClick={() => setMobileView('content')} className={cn("p-2 rounded-xl flex items-center gap-2 text-sm font-medium transition-colors", mobileView === 'content' ? "text-indigo-600 bg-indigo-50" : "text-slate-600")}>
                <FileText className="w-5 h-5" /> Read
              </button>
              <button onClick={() => setMobileView('chat')} className={cn("p-2 rounded-xl flex items-center gap-2 text-sm font-medium transition-colors", mobileView === 'chat' ? "text-indigo-600 bg-indigo-50" : "text-slate-600")}>
                <MessageSquare className="w-5 h-5" /> Chat
              </button>
            </div>

            {/* -- Left Sidebar: Navigation -- */}
            <div
              className={cn(
                "bg-white/40 border-r border-slate-200 lg:block h-full overflow-hidden flex flex-col",
                mobileView === 'nav' ? "block w-full flex-1" : "hidden"
              )}
              style={isDesktop ? { width: leftWidth } : {}}
            >
              <Card className="h-full rounded-none border-0 bg-transparent flex flex-col">
                <div className="p-4 space-y-2">
                  <h3 className="text-xs font-bold text-slate-500 uppercase tracking-wider px-2 mb-2">Sections</h3>
                  {['abstract', 'methodology', 'results', 'conclusions', 'key_findings'].map((section) => (
                    <button
                      key={section}
                      onClick={() => { setActiveSection(section); if (!isDesktop) setMobileView('content'); }}
                      className={cn(
                        "w-full text-left px-4 py-3 rounded-xl text-sm font-medium transition-all duration-200 border border-transparent flex justify-between items-center group",
                        activeSection === section
                          ? "bg-indigo-100 text-indigo-700 border-indigo-200 shadow-sm"
                          : "text-slate-600 hover:bg-slate-100 hover:text-slate-900"
                      )}
                    >
                      <span>{section.replace('_', ' ').charAt(0).toUpperCase() + section.replace('_', ' ').slice(1)}</span>
                      {activeSection === section && <ChevronRight className="w-4 h-4 opacity-50" />}
                    </button>
                  ))}
                </div>
              </Card>
            </div>

            {/* -- Resizer Handle (Left) -- */}
            <div
              className="hidden lg:flex w-4 -ml-2 mr-[-8px] cursor-col-resize items-center justify-center hover:bg-indigo-500/10 transition-colors group z-30 select-none"
              onMouseDown={startResizing('left')}
            >
              <div className="w-1 h-8 bg-slate-300/50 group-hover:bg-indigo-500 rounded-full transition-colors" />
            </div>

            {/* -- Middle: Content -- */}
            <div
              className={cn(
                "flex-1 bg-slate-50/20 lg:block h-full overflow-hidden flex flex-col relative min-w-0 transition-opacity",
                mobileView === 'content' ? "block w-full" : "hidden"
              )}
            >
              <Card className="h-full rounded-none border-0 bg-transparent flex flex-col relative w-full shadow-inner shadow-indigo-100/20">
                <div className="absolute inset-x-0 top-0 h-4 bg-gradient-to-b from-slate-50/20 to-transparent pointer-events-none z-10" />
                <div className="flex-1 overflow-y-auto px-6 py-8 md:px-12 md:py-10 custom-scrollbar relative">
                  <motion.div
                    key={activeSection}
                    initial={{ opacity: 0, y: 10 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ duration: 0.3 }}
                    className="max-w-3xl mx-auto pb-20"
                  >
                    <h2 className="text-3xl font-bold text-slate-900 mb-8 capitalize tracking-tight flex items-center gap-3 border-b border-slate-200 pb-4">
                      {activeSection === 'key_findings' ? <Star className="w-7 h-7 text-amber-500" /> : <FileText className="w-7 h-7 text-indigo-600" />}
                      {activeSection.replace('_', ' ')}
                    </h2>

                    <div className="prose max-w-none text-slate-700 leading-relaxed font-light marker:text-indigo-600">
                      {activeSection === 'key_findings' ? (
                        <ul className="grid gap-4">
                          {(result[activeSection] || []).map((finding, i) => (
                            <li key={i} className="flex items-start gap-4 bg-slate-100 p-5 rounded-2xl border border-slate-200 hover:border-slate-300 transition-all shadow-sm hover:shadow-md hover:shadow-indigo-100/20">
                              <div className="mt-1 p-1 bg-emerald-100 rounded-full">
                                <Check className="w-4 h-4 text-emerald-600 flex-shrink-0" />
                              </div>
                              <span className="text-slate-800">{finding}</span>
                            </li>
                          ))}
                        </ul>
                      ) : (
                        <p className="whitespace-pre-wrap">{result[activeSection] || "Content not available."}</p>
                      )}
                    </div>
                  </motion.div>
                </div>
              </Card>
            </div>

            {/* -- Resizer Handle (Right) -- */}
            <div
              className="hidden lg:flex w-4 -ml-2 mr-[-8px] cursor-col-resize items-center justify-center hover:bg-indigo-500/10 transition-colors group z-30 select-none"
              onMouseDown={startResizing('right')}
            >
              <div className="w-1 h-8 bg-slate-300/50 group-hover:bg-indigo-500 rounded-full transition-colors" />
            </div>

            {/* -- Right: Chat -- */}
            <div
              className={cn(
                "bg-white/40 border-l border-slate-200 lg:block h-full overflow-hidden flex flex-col",
                mobileView === 'chat' ? "block w-full flex-1" : "hidden"
              )}
              style={isDesktop ? { width: rightWidth } : {}}
            >
              <Card className="h-full rounded-none border-0 bg-transparent flex flex-col">
                <div className="p-4 border-b border-slate-200 bg-slate-100 flex items-center justify-between">
                  <h3 className="font-semibold text-slate-900 flex items-center gap-2">
                    <MessageSquare className="w-4 h-4 text-indigo-600" /> Assistant
                  </h3>
                  <span className="text-xs text-slate-500 bg-white px-2 py-1 rounded-md border border-slate-200">AI Agent</span>
                </div>

                <div className="flex-1 overflow-y-auto p-4 space-y-4 custom-scrollbar bg-slate-50/20">
                  {messages.length === 0 && (
                    <div className="flex flex-col items-center justify-center h-full text-slate-400 space-y-2 opacity-50">
                      <MessageSquare className="w-10 h-10 mb-2" />
                      <p className="text-sm">Ask questions about the paper</p>
                    </div>
                  )}
                  {messages.map((msg, i) => (
                    <div key={i} className={cn("flex", msg.role === 'user' ? "justify-end" : "justify-start")}>
                      <div className={cn(
                        "max-w-[90%] rounded-2xl px-4 py-3 text-sm shadow-md",
                        msg.role === 'user'
                          ? "bg-indigo-600 text-white rounded-br-sm"
                          : "bg-white border border-slate-200 text-slate-800 rounded-bl-sm"
                      )}>
                        {msg.content}
                      </div>
                    </div>
                  ))}
                  {chatLoading && (
                    <div className="flex justify-start">
                      <div className="bg-white px-4 py-3 rounded-2xl rounded-bl-none border border-slate-200">
                        <Loader2 className="w-4 h-4 animate-spin text-slate-400" />
                      </div>
                    </div>
                  )}
                </div>

                <div className="p-4 border-t border-slate-200 bg-slate-100/50">
                  <form onSubmit={handleChat} className="flex gap-2">
                    <Input
                      value={chatInput}
                      onChange={(e) => setChatInput(e.target.value)}
                      placeholder="Ask a question..."
                      disabled={chatLoading}
                      className="bg-white border-slate-200 text-slate-900 placeholder:text-slate-400 focus:border-indigo-500 focus:bg-white transition-colors"
                    />
                    <Button type="submit" disabled={chatLoading || !chatInput.trim()} className="rounded-xl px-3 bg-indigo-600 hover:bg-indigo-500 text-white shadow-lg shadow-indigo-500/20">
                      <Zap className="w-4 h-4" />
                    </Button>
                  </form>
                </div>
              </Card>
            </div>
          </div>
        </div >
      ) : (
        // --- UPLOAD VIEW ---
        <div className="flex-1">
          <div className="p-6 h-full flex items-center justify-center">
            <div className="max-w-4xl w-full relative">
              <div className="space-y-6 flex flex-col items-center relative z-10 w-full transition-all duration-300">
                <Card className="p-12 w-full border-slate-200 shadow-2xl shadow-indigo-100/50 items-center justify-center flex flex-col bg-white rounded-3xl">
                  <div className="w-full">
                    <div className="group border-2 border-dashed border-indigo-100 hover:border-indigo-300 bg-indigo-50/30 hover:bg-indigo-50/60 rounded-3xl p-16 text-center transition-all duration-300 cursor-pointer relative flex flex-col items-center justify-center min-h-[400px] w-full">
                      <input type="file" accept=".pdf" onChange={handleUpload} className="absolute inset-0 opacity-0 cursor-pointer z-10" />

                      {analyzing ? (
                        <div className="flex flex-col items-center">
                          <div className="relative mb-6">
                            <div className="absolute inset-0 bg-indigo-500 blur-xl opacity-20 rounded-full animate-pulse"></div>
                            <Loader2 className="w-16 h-16 text-indigo-600 animate-spin relative z-10" />
                          </div>
                          <p className="text-indigo-700 font-bold text-xl animate-pulse">Analyzing your paper...</p>
                          <p className="text-indigo-500 text-sm mt-2">Extracting insights and key findings</p>
                        </div>
                      ) : (
                        <div className="flex flex-col items-center space-y-6">
                          <div className="p-6 bg-white rounded-3xl shadow-xl shadow-indigo-100 mb-2 group-hover:scale-110 group-hover:rotate-3 transition-transform duration-300 ease-out border border-indigo-50">
                            <div className="p-4 bg-indigo-50 rounded-2xl">
                              <Upload className="w-10 h-10 text-indigo-600" />
                            </div>
                          </div>
                          <div>
                            <p className="text-2xl font-bold text-slate-900">Drop your research paper here</p>
                            <p className="text-slate-500 mt-2 font-medium">Support for PDF files up to 10MB</p>
                          </div>
                          <div className="px-6 py-3 rounded-full bg-white border border-slate-200 shadow-sm text-indigo-600 text-sm font-bold group-hover:bg-indigo-600 group-hover:text-white group-hover:border-indigo-600 transition-colors">
                            Click to Browse
                          </div>
                        </div>
                      )}
                    </div>
                  </div>
                </Card>
              </div>
            </div>

            {/* Show floating chat ONLY when NOT in workspace view (i.e. here in upload view) */}
            <div className="fixed bottom-6 right-6 z-50 flex flex-col items-end">
              <AnimatePresence>
                {isChatOpen && (
                  <motion.div
                    initial={{ opacity: 0, scale: 0.9, y: 20 }}
                    animate={{ opacity: 1, scale: 1, y: 0 }}
                    exit={{ opacity: 0, scale: 0.9, y: 20 }}
                    transition={{ duration: 0.2 }}
                    className="mb-4 w-[400px] h-[600px] max-h-[80vh] shadow-2xl rounded-2xl overflow-hidden"
                  >
                    <Card className="flex flex-col h-full border-white/10 bg-slate-900/95 backdrop-blur-xl">
                      <div className="p-4 border-b border-white/10 bg-slate-800/50 backdrop-blur-sm flex justify-between items-center cursor-pointer" onClick={() => setIsChatOpen(false)}>
                        <h2 className="text-lg font-semibold text-white flex items-center">
                          <MessageSquare className="w-5 h-5 mr-2 text-indigo-400" />
                          History Chat
                        </h2>
                        <Button variant="ghost" size="sm" className="h-8 w-8 p-0 text-slate-400 hover:bg-white/5 hover:text-slate-200" onClick={(e) => { e.stopPropagation(); setIsChatOpen(false); }}>
                          <X className="w-4 h-4" />
                        </Button>
                      </div>

                      <div className="flex-1 overflow-y-auto p-4 space-y-4 custom-scrollbar bg-slate-950/50">
                        <div className="text-center text-slate-500 mt-10">
                          <History className="w-12 h-12 mx-auto mb-3 opacity-20" />
                          <p>Select a paper from History to view past chats.</p>
                        </div>
                      </div>
                    </Card>
                  </motion.div>
                )}
              </AnimatePresence>

              <motion.button
                whileHover={{ scale: 1.1 }}
                whileTap={{ scale: 0.9 }}
                onClick={() => setIsChatOpen(!isChatOpen)}
                className="w-14 h-14 bg-indigo-600 hover:bg-indigo-500 text-white rounded-full shadow-lg shadow-indigo-500/30 flex items-center justify-center transition-colors"
                title="View History Chat"
              >
                {isChatOpen ? <X className="w-6 h-6" /> : <MessageSquare className="w-6 h-6" />}
              </motion.button>
            </div>
          </div>
        </div>
      )}
      {/* Alert Modal */}
      <AnimatePresence>
        {alertState.open && (
          <div className="fixed inset-0 z-[100] flex items-center justify-center p-4 bg-black/50 backdrop-blur-sm">
            <motion.div
              initial={{ opacity: 0, scale: 0.95 }}
              animate={{ opacity: 1, scale: 1 }}
              exit={{ opacity: 0, scale: 0.95 }}
              onClick={(e) => e.stopPropagation()}
            >
              <div
                className="max-w-md w-full p-6 rounded-2xl border border-slate-200 shadow-2xl relative"
                style={{ backgroundColor: 'white', color: '#0f172a' }}
              >
                <div className="flex flex-col gap-4 text-center">
                  <div className="w-12 h-12 rounded-full bg-red-100 flex items-center justify-center mx-auto mb-2">
                    <Shield className="w-6 h-6 text-red-600" />
                  </div>
                  <h3 className="text-xl font-bold text-slate-900">{alertState.title}</h3>
                  <p className="text-slate-600">{alertState.message}</p>
                  <Button onClick={closeAlert} className="w-full mt-2 bg-slate-100 hover:bg-slate-200 text-slate-900 shadow-none border border-slate-200">
                    Close
                  </Button>
                </div>
              </div>
            </motion.div>
          </div>
        )}
      </AnimatePresence>
    </div >
  );
};

const GoogleCallback = () => {
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();

  useEffect(() => {
    const token = searchParams.get("token");
    const email = searchParams.get("email");
    const picture = searchParams.get("picture");

    if (token) {
      localStorage.setItem("token", token);
      if (email) localStorage.setItem("userEmail", email);
      if (picture) localStorage.setItem("userPicture", picture);
      navigate("/dashboard");
    } else {
      navigate("/login");
    }
  }, [searchParams, navigate]);

  return <div className="min-h-screen flex items-center justify-center bg-slate-950 text-white">Logging in...</div>;
};

// --- App ---

function App() {
  return (
    <Router>
      <Routes>
        <Route path="/" element={<Landing />} />
        <Route path="/login" element={<Login />} />
        <Route path="/signup" element={<Signup />} />
        <Route path="/dashboard" element={<Dashboard />} />
        <Route path="/pricing" element={<Pricing />} />
        <Route path="/google-callback" element={<GoogleCallback />} />
      </Routes>
    </Router>
  );
}

export default App;
