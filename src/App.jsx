import { useState, useEffect } from 'react';
import { BrowserRouter as Router, Routes, Route, useNavigate, useSearchParams } from 'react-router-dom';
import { GoogleOAuthProvider } from '@react-oauth/google';
import './index.css';

// LAYOUT & AUTH
import NavBar from './components/NavBar';
import Login from './components/Login';

// PUBLIC PAGES
import Home from './pages/Home';
import About from './pages/About';
import Contact from './pages/Contact';
import Payment from './pages/Payment';

// PROTECTED PAGES
import Dashboard from './pages/Dashboard';
import Kabinet from './pages/Kabinet';

// SMART TABLES (Теперь берутся из новой папки)
import UsersTable from './pages/tables/UsersTable';
import OrdersTable from './pages/tables/OrdersTable';
// ДОБАВЬ ЭТИ ВМЕСТО ProductsTable:
import HubsTable from './pages/tables/HubsTable';
import CamerasTable from './pages/tables/CamerasTable';
import LightingTable from './pages/tables/LightingTable';
import SensorsTable from './pages/tables/SensorsTable';
import LogsTable from './pages/tables/LogsTable';
import MessagesTable from './pages/tables/MessagesTable';

const clientId = '631083577297-n17acu7qspb1n9n8lhmr8q43b4vbpif1.apps.googleusercontent.com';

// Обработчик реферальных ссылок
function ReferralHandler({ setShowRegister, setShowLogin }) {
  const [searchParams] = useSearchParams();
  useEffect(() => {
    const ref = searchParams.get('ref');
    if (ref) {
      localStorage.setItem('referral_code', ref);
      setShowRegister(true);
      setShowLogin(false);
    }
  }, [searchParams, setShowRegister, setShowLogin]);
  return null;
}

function AppContent() {
  const [isAuthenticated, setIsAuthenticated] = useState(!!localStorage.getItem('token'));
  const [user, setUser] = useState(JSON.parse(localStorage.getItem('userInfo')) || null);
  const [showLogin, setShowLogin] = useState(false);
  const [showRegister, setShowRegister] = useState(false);
  const navigate = useNavigate();

  const handleAuth = (userInfo) => {
    setIsAuthenticated(true);
    setUser(userInfo);
    localStorage.setItem('userInfo', JSON.stringify(userInfo));
    setShowLogin(false);
    setShowRegister(false);
    navigate('/dashboard');
  };

  const handleLogout = () => {
    setIsAuthenticated(false);
    setUser(null);
    localStorage.clear();
    navigate('/');
  };

  return (
    <div className="bg-[var(--bg-color)] min-h-screen text-[var(--text-color)] font-sans transition-colors duration-300 relative selection:bg-[var(--accent-color)] selection:text-black">
      
      <NavBar user={user} onLogin={() => setShowLogin(true)} onLogout={handleLogout} />
      
      <Login 
        showLogin={showLogin} 
        showRegister={showRegister}
        onClose={() => { setShowLogin(false); setShowRegister(false); }}
        onSuccess={handleAuth}
        onSwitchToReg={() => { setShowLogin(false); setShowRegister(true); }}
        onSwitchToLogin={() => { setShowRegister(false); setShowLogin(true); }}
      />
      
      <ReferralHandler setShowRegister={setShowRegister} setShowLogin={setShowLogin} />

      <Routes>
        {/* === PUBLIC ROUTES === */}
        <Route path="/" element={<Home />} />
        <Route path="/about" element={<About />} />
        <Route path="/contact" element={<Contact />} />
        <Route path="/payment" element={<Payment />} />
        
        {/* === AUTH PROTECTED ROUTES === */}
        {isAuthenticated ? (
          <>
            <Route path="/dashboard" element={<div className="pt-24 px-4"><Dashboard user={user} /></div>} />
            <Route path="/kabinet" element={<div className="pt-24 px-4"><Kabinet user={user} /></div>} />
            
            
            {/* ТАБЛИЦЫ ОБОРУДОВАНИЯ (Доступны всем авторизованным) */}
            <Route path="/hubs" element={<HubsTable user={user} />} />
            <Route path="/cameras" element={<CamerasTable user={user} />} />
            <Route path="/lighting" element={<LightingTable user={user} />} />
            <Route path="/sensors" element={<SensorsTable user={user} />} />

            {/* ТАБЛИЦЫ УПРАВЛЕНИЯ (Админские) */}
            <Route path="/users" element={<UsersTable user={user} />} />
            <Route path="/orders" element={<OrdersTable user={user} />} />
            <Route path="/admin/logs" element={<LogsTable user={user} />} />
            <Route path="/messages" element={<MessagesTable />} />
          </>
        ) : (
          // Если не авторизован - показываем заглушку или редирект
          <Route path="*" element={
            <div className="h-screen flex flex-col items-center justify-center gap-4">
              <h1 className="text-4xl font-black text-red-500 tracking-widest">403 FORBIDDEN</h1>
              <button onClick={() => setShowLogin(true)} className="btn-neon px-6 py-2">ВОЙТИ В СИСТЕМУ</button>
            </div>
          } />
        )}
      </Routes>
    </div>
  );
}

export default function App() {
  return (
    <GoogleOAuthProvider clientId={clientId}>
      <Router>
        <AppContent />
      </Router>
    </GoogleOAuthProvider>
  );
}
