import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { Link, useNavigate, useLocation } from 'react-router-dom';
import { motion } from 'framer-motion';
import { Cpu, LogOut, User, MessageCircle } from 'lucide-react';
import LightDark from './lightdark';
import UserAvatar from './UserAvatar';
import SupportChat from './SupportChat';

const navLinks = [
  { path: '/', label: 'ГЛАВНАЯ' },
  { path: '/about', label: 'О НАС' },
  { path: '/contact', label: 'КОНТАКТЫ' },
];

const catalogLink = [
  { path: '/dashboard', label: 'КАТАЛОГ' }
];

const NavBar = ({ user, onLogin, onLogout }) => {
  const [theme, setTheme] = useState(localStorage.getItem('theme') || 'dark');
  const [hoveredPath, setHoveredPath] = useState(null);
  const [unreadCount, setUnreadCount] = useState(0);
  const [isChatOpen, setIsChatOpen] = useState(false); 
  const navigate = useNavigate();
  const location = useLocation();

  const isAdmin = user?.role === 'admin';
  const roleLabel = isAdmin ? 'ADMIN' : 'OPERATOR';
  const roleColorClass = isAdmin ? 'text-red-500' : 'text-[var(--accent-color)]';
  const adminColorClass = 'text-red-500';

  // --- 1. ТАБЛИЦЫ ОБОРУДОВАНИЯ (ЧИСТЫЕ ПУТИ ДЛЯ ВСЕХ) ---
  const equipmentLinks = [
    { path: '/hubs', label: 'ХАБЫ' },
    { path: '/cameras', label: 'КАМЕРЫ' },
    { path: '/lighting', label: 'СВЕТ' },
    { path: '/sensors', label: 'ДАТЧИКИ' },
  ];

  // --- 2. ТАБЛИЦЫ УПРАВЛЕНИЯ (ТОЛЬКО АДМИНУ) ---
  const adminManagementLinks = [
    { path: '/users', label: 'ПОЛЬЗОВАТЕЛИ' },
    { path: '/orders', label: 'ЗАКАЗЫ' },
    { path: '/messages', label: 'ЧАТЫ' },
    { path: '/admin/logs', label: 'ЛОГИ' },
  ];

  useEffect(() => {
    document.body.className = theme;
    localStorage.setItem('theme', theme);
  }, [theme]);

  useEffect(() => {
    if (user) {
        const checkUnread = async () => {
            try {
                const token = localStorage.getItem('token');
                const res = await axios.get(`https://diplomreact.apt142.ru/messages/unread?email=${user.email}`, {
                    headers: { Authorization: `Bearer ${token}` }
                });
                setUnreadCount(res.data.count);
            } catch (e) {}
        };
        checkUnread();
        const interval = setInterval(checkUnread, 5000);
        return () => clearInterval(interval);
    }
  }, [user]);

  const toggleTheme = () => setTheme(theme === 'dark' ? 'light' : 'dark');

  const renderMenu = (links) => (
    <div className="relative flex items-center bg-[var(--input-bg)]/50 backdrop-blur-md border border-[var(--glass-border)] px-1 py-1 rounded-none shadow-sm overflow-x-auto no-scrollbar"> 
      {links.map((link) => (
        <Link 
          key={link.path}
          to={link.path}
          onMouseEnter={() => setHoveredPath(link.path)}
          onMouseLeave={() => setHoveredPath(null)}
          className="relative px-3 xl:px-4 py-3 text-[9px] xl:text-[10px] font-bold tracking-widest text-[var(--text-color)] transition-colors hover:text-[var(--accent-color)] uppercase z-10 whitespace-nowrap"
        >
          {link.label}
          
          {hoveredPath === link.path && (
            <motion.div
              layoutId="navbar-hover"
              className="absolute inset-0 bg-[var(--accent-color)]/10 border border-[var(--accent-color)]/50 z-[-1]"
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              transition={{ type: "spring", bounce: 0.2, duration: 0.6 }}
            >
                <div className="absolute bottom-0 left-0 w-1 h-1 border-l border-b border-[var(--accent-color)]" />
                <div className="absolute top-0 right-0 w-1 h-1 border-r border-t border-[var(--accent-color)]" />
            </motion.div>
          )}

          {location.pathname === link.path && (
            <motion.div 
                layoutId="navbar-active"
                className="absolute bottom-0 left-0 right-0 h-[2px] bg-[var(--accent-color)] shadow-[0_0_10px_var(--accent-color)]"
            />
          )}
        </Link>
      ))}
    </div>
  );

  return (
    <>
      <nav className="fixed top-0 w-full z-50 glass h-24 flex items-center transition-all duration-300 border-b border-[var(--glass-border)]">
        <div className="max-w-[1900px] mx-auto px-6 w-full flex items-center justify-between gap-4">
          
          <Link to="/" className="flex items-center gap-3 group shrink-0">
            <div className="p-2 bg-[var(--accent-color)]/10 rounded-lg border border-[var(--accent-color)]/30 group-hover:shadow-[0_0_20px_var(--accent-color)] transition-all">
              <Cpu className="text-[var(--accent-color)] w-6 h-6" />
            </div>
            <span className="font-black text-2xl tracking-widest hidden 2xl:block text-[var(--text-color)]">NEXUS</span>
          </Link>

          <div className="hidden lg:flex items-center gap-4 flex-1 justify-center">
             {renderMenu(navLinks)}
             
             {user && (
               <>
                  <div className="w-px h-8 bg-[var(--glass-border)] mx-1" /> 
                  {renderMenu(catalogLink)}

                  <div className="w-px h-8 bg-[var(--glass-border)] mx-1" /> 
                  {/* Группа таблиц оборудования доступна всем авторизованным */}
                  {renderMenu(equipmentLinks)}

                  {isAdmin && (
                    <>
                      <div className="w-px h-8 bg-[var(--glass-border)] mx-1" /> 
                      <div className="flex items-center gap-2">
                        <span className={`text-[8px] font-black tracking-widest opacity-70 hidden xl:block ${adminColorClass}`}>
                            ADMIN_DB:
                        </span>
                        {renderMenu(adminManagementLinks)}
                      </div>
                    </>
                  )}
               </>
             )}
          </div>

          <div className="flex items-center gap-4 shrink-0">
            <div className="scale-75 origin-right hidden sm:block">
               <LightDark toggleTheme={toggleTheme} isLight={theme === 'light'} />
            </div>

            {user ? (
              <div className="flex items-center gap-4 pl-4 border-l border-[var(--glass-border)]">
                <button onClick={() => { setIsChatOpen(!isChatOpen); setUnreadCount(0); }} 
                        className={`p-2 rounded-full transition-all duration-300 relative ${isChatOpen ? 'bg-[var(--accent-color)] text-black' : 'text-[var(--text-color)] hover:text-[var(--accent-color)] bg-[var(--accent-color)]/10'}`}>
                  <MessageCircle size={18} />
                  {unreadCount > 0 && <span className="absolute -top-1 -right-1 w-2.5 h-2.5 bg-red-500 rounded-full animate-pulse shadow-[0_0_10px_red]" />}
                </button>

                <div onClick={() => navigate('/kabinet')} className="flex items-center gap-3 cursor-pointer group">
                  <div className="text-right hidden sm:block">
                    <span className={`text-[8px] uppercase block font-black tracking-widest transition-colors ${roleColorClass}`}>{roleLabel}</span>
                    <span className="text-xs font-bold block leading-none text-[var(--text-color)]">{user.name}</span>
                  </div>
                  <UserAvatar user={user} className="w-9 h-9 rounded-full border border-transparent group-hover:border-[var(--accent-color)] transition-all" />
                </div>
                
                <button onClick={onLogout} className="text-[var(--text-color)] opacity-50 hover:opacity-100 hover:text-red-500 transition-all">
                  <LogOut size={20} />
                </button>
              </div>
            ) : (
              <button onClick={onLogin} className="btn-neon text-[10px] font-bold px-5 py-3 flex items-center gap-2 shadow-lg tracking-widest uppercase">
                <User size={14}/> Войти
              </button>
            )}
          </div>
        </div>
      </nav>

      {user && <SupportChat isOpen={isChatOpen} onClose={() => setIsChatOpen(false)} user={user} />}
    </>
  );
};

export default NavBar;
