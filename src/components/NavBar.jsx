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
  const menuLabel = isAdmin ? 'ADMIN MENU:' : 'MENU:';
  const roleLabel = isAdmin ? 'ADMIN' : 'OPERATOR';
  const roleColorClass = isAdmin ? 'text-red-500' : 'text-[var(--accent-color)]';
  const menuLabelColorClass = isAdmin ? 'text-red-500' : 'text-[var(--accent-color)]';
  const tableLinks = [
    { path: '/users', label: 'ПОЛЬЗОВАТЕЛИ' },
    { path: '/orders', label: 'ЗАКАЗЫ' },
    { path: '/products', label: 'ТОВАРЫ' },
    { path: '/messages', label: 'СООБЩЕНИЯ' },
  ];
  if (isAdmin) {
    tableLinks.push({ path: '/admin/logs', label: 'ЛОГИ' });
  }
  useEffect(() => {
    document.body.className = theme;
    localStorage.setItem('theme', theme);
  }, [theme]);

  // ОПРОС НЕПРОЧИТАННЫХ
  useEffect(() => {
    if (user) {
        const checkUnread = async () => {
            try {
                const token = localStorage.getItem('token');
                const res = await axios.get(`https://test.apt142.ru/messages/unread?email=${user.email}`, {
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

  // ФУНКЦИЯ РЕНДЕРА КНОПОК МЕНЮ
  const renderMenu = (links) => (
    <div className="relative flex items-center bg-[var(--input-bg)]/50 backdrop-blur-md border border-[var(--glass-border)] px-1 py-1 rounded-none shadow-sm"> 
      {links.map((link) => (
        <Link 
          key={link.path}
          to={link.path}
          onMouseEnter={() => setHoveredPath(link.path)}
          onMouseLeave={() => setHoveredPath(null)}
          className="relative px-5 py-3 text-[10px] xl:text-xs font-bold tracking-widest text-[var(--text-color)] transition-colors hover:text-[var(--accent-color)] uppercase z-10"
        >
          {link.label}
          
          {/* Фон при наведении */}
          {hoveredPath === link.path && (
            <motion.div
              layoutId="navbar-hover"
              className="absolute inset-0 bg-[var(--accent-color)]/10 border border-[var(--accent-color)]/50 z-[-1]"
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              transition={{ type: "spring", bounce: 0.2, duration: 0.6 }}
            >
                <div className="absolute bottom-0 left-0 w-1.5 h-1.5 border-l-2 border-b-2 border-[var(--accent-color)]" />
                <div className="absolute top-0 right-0 w-1.5 h-1.5 border-r-2 border-t-2 border-[var(--accent-color)]" />
            </motion.div>
          )}

          {/* Активная вкладка */}
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
        <div className="max-w-[1900px] mx-auto px-6 w-full flex items-center justify-between">
          
          {/* ЛОГОТИП */}
          <Link to="/" className="flex items-center gap-3 group mr-4 shrink-0">
            <div className="p-2 bg-[var(--accent-color)]/10 rounded-lg border border-[var(--accent-color)]/30 group-hover:shadow-[0_0_20px_var(--accent-color)] transition-all">
              <Cpu className="text-[var(--accent-color)] w-6 h-6" />
            </div>
            <span className="font-black text-2xl tracking-widest hidden xl:block text-[var(--text-color)]">
              NEXUS
            </span>
          </Link>

          {/* ЦЕНТРАЛЬНАЯ ЧАСТЬ */}
          <div className="hidden lg:flex items-center gap-6">
             
             {/* 1. ОБЩЕЕ МЕНЮ (Главная, О проекте...) */}
             {renderMenu(navLinks)}
             
             {/* 2. БЛОК АВТОРИЗОВАННОГО ПОЛЬЗОВАТЕЛЯ */}
             {user && (
               <div className="flex items-center gap-2">
                  {/* Разделитель */}
                  <div className="w-px h-8 bg-[var(--glass-border)] mx-2" /> 
                  
                  {/* КНОПКА "КАТАЛОГ" (КАК И ПРОСИЛ: ОТДЕЛЬНО, НО В ТОМ ЖЕ СТИЛЕ) */}
                  <span className={`text-[9px] font-black tracking-widest opacity-70 ${menuLabelColorClass}`}>
                    {menuLabel}
                  </span>
                  {renderMenu(tableLinks)}

                  {/* Разделитель */}
                  <div className="w-px h-8 bg-[var(--glass-border)] mx-2" /> 

                  {/* МЕНЮ ТАБЛИЦ */}
                  {renderMenu(catalogLink)}
               </div>
             )}
          </div>

          {/* ПРАВАЯ ЧАСТЬ */}
          <div className="flex items-center gap-6 shrink-0">
            
            <div className="scale-75 origin-right">
               <LightDark toggleTheme={toggleTheme} isLight={theme === 'light'} />
            </div>

            {user ? (
              <div className="flex items-center gap-4 pl-6 border-l border-[var(--glass-border)]">
                
                {/* ЧАТ */}
                <button 
                    onClick={() => { setIsChatOpen(!isChatOpen); setUnreadCount(0); }} 
                    className={`p-2 rounded-full transition-all duration-300 relative ${isChatOpen ? 'bg-[var(--accent-color)] text-black' : 'text-[var(--text-color)] hover:text-[var(--accent-color)] bg-[var(--accent-color)]/10'}`} 
                    title="Поддержка"
                >
                  <MessageCircle size={20} />
                    {unreadCount > 0 && (
                    <span className="absolute -top-1 -right-1 w-2 h-2 bg-red-500 rounded-full animate-pulse shadow-[0_0_10px_red]" />
                    )}
                </button>

                {/* ПРОФИЛЬ -> КАБИНЕТ */}
                <div 
                  onClick={() => navigate('/kabinet')}
                  className="flex items-center gap-3 cursor-pointer group"
                >
                  <div className="text-right hidden xl:block">
                    <span className={`text-[9px] uppercase block font-black tracking-widest group-hover:text-purple-400 transition-colors ${roleColorClass}`}>
                      {roleLabel}
                    </span>
                    <span className="text-sm font-bold block leading-none text-[var(--text-color)]">{user.name}</span>
                  </div>
                  <UserAvatar user={user} className="w-10 h-10 rounded-full group-hover:border-[var(--accent-color)] transition-colors" />
                </div>
                
                <button onClick={onLogout} className="text-[var(--text-color)] opacity-50 hover:opacity-100 hover:text-red-500 transition-all" title="Выйти">
                  <LogOut size={22} />
                </button>
              </div>
            ) : (
              <button onClick={onLogin} className="btn-neon text-xs font-bold px-6 py-3 flex items-center gap-2 shadow-lg tracking-widest rounded-none">
                <User size={16}/> ВОЙТИ
              </button>
            )}
          </div>
        </div>
      </nav>

      {/* ОКНО ЧАТА */}
      {user && (
        <SupportChat 
          isOpen={isChatOpen} 
          onClose={() => setIsChatOpen(false)} 
          user={user} 
        />
      )}
    </>
  );
};

export default NavBar;