import { useState } from 'react';
import axios from 'axios';
import { motion, AnimatePresence } from 'framer-motion';
import { X, User, Lock, Mail, Fingerprint, ScanFace, ArrowRight } from 'lucide-react';
import { useGoogleLogin } from '@react-oauth/google';
import GoogleButton from './google'; 

const Login = ({ showLogin, showRegister, onClose, onSuccess, onSwitchToReg, onSwitchToLogin }) => {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [name, setName] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  // Логика Google входа
  const googleLogin = useGoogleLogin({
    onSuccess: async (tokenResponse) => {
      try {
        const res = await axios.post('https://test.apt142.ru/auth/google', {
          access_token: tokenResponse.access_token,
        });
        localStorage.setItem('token', res.data.token);
        onSuccess(res.data.user);
      } catch (err) {
        setError('Ошибка Google авторизации');
      }
    },
    onError: () => setError('Google вход не удался'),
  });

  const handleSubmit = async (e, isRegister) => {
    e.preventDefault();
    setError('');
    setLoading(true);
    
    try {
      // Имитация задержки для красоты анимации
      await new Promise(resolve => setTimeout(resolve, 800));

      const endpoint = isRegister ? 'https://test.apt142.ru/register' : 'https://test.apt142.ru/login';
      const payload = isRegister 
        ? { email, password, name, referral_code: localStorage.getItem('referral_code') } 
        : { email, password };
      
      const res = await axios.post(endpoint, payload);
      localStorage.setItem('token', res.data.token);
      onSuccess(res.data.user);
    } catch (err) {
      setError(err.response?.data?.error || 'Ошибка доступа: Неверные данные');
    } finally {
      setLoading(false);
    }
  };

  if (!showLogin && !showRegister) return null;

  const isRegister = showRegister;

  return (
    <AnimatePresence>
      {/* Убрал onClick={onClose} отсюда. Теперь клик по фону ничего не делает */}
      <div className="fixed inset-0 z-[100] flex items-center justify-center bg-black/90 backdrop-blur-md cursor-default">
        
        {/* ФОНОВЫЕ ЭФФЕКТЫ */}
        <div className="absolute inset-0 overflow-hidden pointer-events-none">
           <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[500px] h-[500px] bg-[var(--accent-color)]/20 blur-[100px] rounded-full" />
        </div>

        <motion.div 
          initial={{ scale: 0.9, opacity: 0, y: 20 }} 
          animate={{ scale: 1, opacity: 1, y: 0 }} 
          exit={{ scale: 0.9, opacity: 0, y: 20 }}
          transition={{ type: "spring", duration: 0.5 }}
          className="relative w-full max-w-md mx-4"
          onClick={e => e.stopPropagation()}
        >
          {/* ОСНОВНОЙ КОНТЕЙНЕР (СТЕКЛО) */}
          <div className="glass bg-[#0b0c15]/80 p-1 rounded-[2rem] border border-[var(--glass-border)] shadow-[0_0_50px_rgba(0,0,0,0.5)] overflow-hidden">
            
            {/* ВЕРХНЯЯ ПОЛОСА ЗАГРУЗКИ */}
            {loading && (
               <motion.div 
                 initial={{ width: 0 }} animate={{ width: "100%" }} 
                 className="h-1 bg-[var(--accent-color)] absolute top-0 left-0 z-50"
               />
            )}

            <div className="relative p-8 md:p-10 bg-[var(--card-bg)]/40 rounded-[1.8rem]">
                
                {/* === КРЕСТИК (ЗАКРЫВАЕТ ТОЛЬКО ОН) === */}
                <button 
                  onClick={onClose} 
                  className="absolute top-4 right-4 z-50 group flex items-center justify-center w-10 h-10 rounded-xl bg-white/5 border border-white/10 hover:bg-red-500/10 hover:border-red-500 transition-all duration-300"
                  title="Закрыть терминал"
                >
                  <X 
                    size={20} 
                    className="text-gray-400 group-hover:text-red-500 group-hover:rotate-90 transition-all duration-300" 
                  />
                </button>

                {/* ДЕКОРАТИВНЫЕ УГОЛКИ */}
                <div className="absolute top-8 left-8 w-4 h-4 border-t-2 border-l-2 border-[var(--accent-color)] opacity-30" />
                <div className="absolute bottom-8 left-8 w-4 h-4 border-b-2 border-l-2 border-[var(--accent-color)] opacity-30" />
                <div className="absolute bottom-8 right-8 w-4 h-4 border-b-2 border-r-2 border-[var(--accent-color)] opacity-30" />

                {/* ЗАГОЛОВОК */}
                <div className="text-center mb-8 mt-2">
                  <div className="flex justify-center mb-4">
                     <div className="p-4 bg-[var(--accent-color)]/10 rounded-full border border-[var(--accent-color)]/30 relative">
                        {isRegister ? <Fingerprint size={32} className="text-[var(--accent-color)]" /> : <ScanFace size={32} className="text-[var(--accent-color)]" />}
                        <div className="absolute inset-0 rounded-full animate-ping bg-[var(--accent-color)]/20" />
                     </div>
                  </div>
                  <h2 className="text-3xl font-black text-[var(--text-color)] tracking-tighter uppercase mb-1">
                    {isRegister ? 'Инициализация' : 'Вход в систему'}
                  </h2>
                  <p className="text-xs font-mono text-[var(--accent-color)] opacity-70 tracking-[0.2em]">
                    SECURE CONNECTION ESTABLISHED
                  </p>
                </div>
                
                {/* ОШИБКА */}
                <AnimatePresence>
                  {error && (
                    <motion.div 
                      initial={{ opacity: 0, height: 0 }} animate={{ opacity: 1, height: 'auto' }} exit={{ opacity: 0, height: 0 }}
                      className="bg-red-500/10 border border-red-500/30 text-red-400 p-3 rounded-xl mb-6 text-center text-sm font-bold flex items-center justify-center gap-2"
                    >
                      <Lock size={14} /> {error}
                    </motion.div>
                  )}
                </AnimatePresence>
                
                {/* ФОРМА */}
                <form onSubmit={e => handleSubmit(e, isRegister)} className="space-y-5 relative z-10">
                  
                  {isRegister && (
                    <div className="group relative">
                      <User className="absolute left-4 top-1/2 -translate-y-1/2 text-gray-500 group-focus-within:text-[var(--accent-color)] transition-colors" size={20} />
                      <input 
                        className="w-full bg-[#000]/20 border border-[var(--glass-border)] rounded-xl py-4 pl-12 pr-4 text-[var(--text-color)] outline-none focus:border-[var(--accent-color)] focus:shadow-[0_0_20px_rgba(0,243,255,0.1)] transition-all font-mono placeholder:text-gray-600" 
                        placeholder="Позывной (Имя)" 
                        value={name} 
                        onChange={e => setName(e.target.value)} 
                        required
                      />
                    </div>
                  )}

                  <div className="group relative">
                    <Mail className="absolute left-4 top-1/2 -translate-y-1/2 text-gray-500 group-focus-within:text-[var(--accent-color)] transition-colors" size={20} />
                    <input 
                      className="w-full bg-[#000]/20 border border-[var(--glass-border)] rounded-xl py-4 pl-12 pr-4 text-[var(--text-color)] outline-none focus:border-[var(--accent-color)] focus:shadow-[0_0_20px_rgba(0,243,255,0.1)] transition-all font-mono placeholder:text-gray-600" 
                      type="email" 
                      placeholder="Электронная почта" 
                      value={email} 
                      onChange={e => setEmail(e.target.value)} 
                      required
                    />
                  </div>

                  <div className="group relative">
                    <Lock className="absolute left-4 top-1/2 -translate-y-1/2 text-gray-500 group-focus-within:text-[var(--accent-color)] transition-colors" size={20} />
                    <input 
                      className="w-full bg-[#000]/20 border border-[var(--glass-border)] rounded-xl py-4 pl-12 pr-4 text-[var(--text-color)] outline-none focus:border-[var(--accent-color)] focus:shadow-[0_0_20px_rgba(0,243,255,0.1)] transition-all font-mono placeholder:text-gray-600" 
                      type="password" 
                      placeholder="Код доступа (Пароль)" 
                      value={password} 
                      onChange={e => setPassword(e.target.value)} 
                      required
                    />
                  </div>
                  
                  <button 
                    disabled={loading}
                    className="btn-neon w-full py-4 text-base font-bold tracking-widest flex justify-center items-center gap-2 group disabled:opacity-50 disabled:cursor-not-allowed"
                  >
                    {loading ? (
                      <span className="animate-pulse">ОБРАБОТКА...</span>
                    ) : (
                      <>
                        {isRegister ? 'ЗАРЕГИСТРИРОВАТЬСЯ' : 'АВТОРИЗАЦИЯ'} 
                        <ArrowRight size={18} className="group-hover:translate-x-1 transition-transform"/>
                      </>
                    )}
                  </button>
                </form>

                {/* РАЗДЕЛИТЕЛЬ */}
                <div className="my-6 flex items-center justify-between">
                  <span className="h-px bg-gradient-to-r from-transparent to-gray-700 flex-1"></span>
                  <span className="text-[10px] font-bold text-gray-500 px-3 uppercase tracking-widest">Или через соц.сети</span>
                  <span className="h-px bg-gradient-to-l from-transparent to-gray-700 flex-1"></span>
                </div>

                <div className="flex justify-center">
                   <div className="w-full transform transition-transform hover:scale-[1.02]">
                      <GoogleButton onClick={() => googleLogin()} />
                   </div>
                </div>

                {/* ПЕРЕКЛЮЧАТЕЛЬ */}
                <div className="mt-8 text-center">
                   <p className="text-sm text-gray-500 mb-2">
                     {isRegister ? 'Уже есть доступ?' : 'Нет идентификатора?'}
                   </p>
                   <button 
                     className="text-[var(--accent-color)] font-bold uppercase tracking-wider hover:text-white transition-colors border-b border-transparent hover:border-[var(--accent-color)] pb-0.5"
                     onClick={isRegister ? onSwitchToLogin : onSwitchToReg}
                   >
                     {isRegister ? 'Войти в систему' : 'Запросить доступ'}
                   </button>
                </div>

            </div>
          </div>
        </motion.div>
      </div>
    </AnimatePresence>
  );
};

export default Login;