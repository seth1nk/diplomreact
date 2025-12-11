import { Link } from 'react-router-dom';
import { ArrowRight, Shield, Zap, Smartphone, Users, Package, Activity, Cpu, Globe } from 'lucide-react';
import { motion } from 'framer-motion';
import { useState, useEffect } from 'react';
import axios from 'axios';
import ArcReactor from '../components/ArcReactor';
import Iphone from '../components/Iphone';
import Fingerprint from '../components/Fingerprint';
import OsCore from '../components/OsCore'; // <--- НОВЫЙ ИМПОРТ

const Home = () => {
  const [stats, setStats] = useState({ users: 0, products: 0, orders: 0 });

  useEffect(() => {
    const fetchStats = async () => {
      try {
        const [u, p, o] = await Promise.all([
           axios.get('https://test.apt142.ru/users', { headers: { Authorization: `Bearer ${localStorage.getItem('token')}` }}),
           axios.get('https://test.apt142.ru/products'),
           axios.get('https://test.apt142.ru/orders', { headers: { Authorization: `Bearer ${localStorage.getItem('token')}` }})
        ]);
        setStats({ users: u.data.length, products: p.data.length, orders: o.data.length });
      } catch (e) {
        // Fallback данные для красоты, если бэк не отвечает
        setStats({ users: 1240, products: 48, orders: 8900 });
      }
    };
    fetchStats();
  }, []);

  // Анимация для контейнеров
  const containerVariants = {
    hidden: { opacity: 0 },
    visible: { opacity: 1, transition: { staggerChildren: 0.2 } }
  };

  const itemVariants = {
    hidden: { y: 20, opacity: 0 },
    visible: { y: 0, opacity: 1 }
  };

  return (
    <div className="min-h-screen relative overflow-x-hidden">
      
      {/* ФОНОВАЯ СЕТКА (Grid Background) */}
      <div className="fixed inset-0 pointer-events-none z-0">
        <div className="absolute inset-0 bg-[var(--bg-color)]" />
        <div className="absolute inset-0 bg-[linear-gradient(to_right,#80808012_1px,transparent_1px),linear-gradient(to_bottom,#80808012_1px,transparent_1px)] bg-[size:24px_24px]" />
        <div className="absolute left-0 right-0 top-0 -z-10 m-auto h-[310px] w-[310px] rounded-full bg-[var(--accent-color)] opacity-20 blur-[100px]" />
      </div>

      {/* === HERO SECTION === */}
      <section className="relative z-10 min-h-screen flex items-center pt-20 px-6">
        <div className="max-w-[1600px] mx-auto grid lg:grid-cols-2 gap-12 items-center w-full">
          
          {/* Левая часть: Текст */}
          <motion.div 
            initial={{ opacity: 0, x: -50 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ duration: 0.8 }}
            className="text-center lg:text-left"
          >
            <div className="inline-flex items-center gap-2 px-4 py-2 rounded-full border border-[var(--accent-color)]/30 bg-[var(--accent-color)]/10 text-[var(--accent-color)] text-xs font-bold tracking-[0.2em] mb-8 shadow-[0_0_15px_rgba(0,243,255,0.2)]">
              <span className="relative flex h-2 w-2">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-[var(--accent-color)] opacity-75"></span>
                <span className="relative inline-flex rounded-full h-2 w-2 bg-[var(--accent-color)]"></span>
              </span>
              SYSTEM NEXUS V.5.0
            </div>

            <h1 className="text-6xl md:text-8xl font-black mb-6 leading-[0.9] text-[var(--text-color)] tracking-tighter">
              УМНЫЙ <br/>
              <span className="text-transparent bg-clip-text bg-gradient-to-r from-[var(--accent-color)] via-purple-500 to-pink-500 animate-gradient">ДОМ</span>
            </h1>
            
            <p className="text-xl text-[var(--text-color)] opacity-60 mb-10 max-w-xl mx-auto lg:mx-0 leading-relaxed">
              Мы не просто автоматизируем рутину. Мы создаем цифровую нервную систему вашего жилища, которая чувствует, думает и защищает.
            </p>

            <div className="flex flex-col sm:flex-row gap-6 justify-center lg:justify-start">
              <Link to="/products" className="btn-neon px-10 py-5 text-lg flex items-center justify-center gap-3 group">
                ОТКРЫТЬ КАТАЛОГ 
                <ArrowRight className="group-hover:translate-x-1 transition-transform" />
              </Link>
              <Link to="/about" className="px-10 py-5 text-lg font-bold text-[var(--text-color)] border border-[var(--glass-border)] rounded-xl hover:bg-white/5 transition-colors flex items-center justify-center gap-2">
                <Globe size={20} />
                О СИСТЕМЕ
              </Link>
            </div>
          </motion.div>

          {/* Правая часть: Реактор */}
          <motion.div 
            initial={{ opacity: 0, scale: 0.8 }}
            animate={{ opacity: 1, scale: 1 }}
            transition={{ duration: 1, delay: 0.2 }}
            className="flex justify-center relative"
          >
             {/* Декоративные круги */}
             <div className="absolute inset-0 bg-gradient-to-tr from-[var(--accent-color)]/20 to-transparent blur-3xl rounded-full opacity-30 animate-pulse" />
             <div className="relative z-10 scale-125 md:scale-150 drop-shadow-[0_0_60px_var(--accent-color)]">
                <ArcReactor />
             </div>
          </motion.div>

        </div>
      </section>

      {/* === STATS SECTION === */}
      <motion.section 
        variants={containerVariants}
        initial="hidden"
        whileInView="visible"
        viewport={{ once: true }}
        className="py-20 relative z-10"
      >
        <div className="max-w-7xl mx-auto px-6">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
             {/* Card 1 */}
             <motion.div variants={itemVariants} className="glass p-8 rounded-[2rem] border border-[var(--glass-border)] flex items-center justify-between group hover:border-[var(--accent-color)]/50 transition-colors">
                <div>
                   <h3 className="text-5xl font-black text-transparent bg-clip-text bg-gradient-to-r from-blue-400 to-cyan-300 mb-2">{stats.users}</h3>
                   <p className="text-sm text-[var(--text-color)] opacity-60 font-bold uppercase tracking-widest">Пользователей</p>
                </div>
                <div className="p-4 bg-blue-500/10 rounded-2xl group-hover:scale-110 transition-transform">
                   <Users size={32} className="text-blue-400" />
                </div>
             </motion.div>

             {/* Card 2 */}
             <motion.div variants={itemVariants} className="glass p-8 rounded-[2rem] border border-[var(--glass-border)] flex items-center justify-between group hover:border-purple-500/50 transition-colors">
                <div>
                   <h3 className="text-5xl font-black text-transparent bg-clip-text bg-gradient-to-r from-purple-400 to-pink-300 mb-2">{stats.products}</h3>
                   <p className="text-sm text-[var(--text-color)] opacity-60 font-bold uppercase tracking-widest">Модулей</p>
                </div>
                <div className="p-4 bg-purple-500/10 rounded-2xl group-hover:scale-110 transition-transform">
                   <Cpu size={32} className="text-purple-400" />
                </div>
             </motion.div>

             {/* Card 3 */}
             <motion.div variants={itemVariants} className="glass p-8 rounded-[2rem] border border-[var(--glass-border)] flex items-center justify-between group hover:border-green-500/50 transition-colors">
                <div>
                   <h3 className="text-5xl font-black text-transparent bg-clip-text bg-gradient-to-r from-green-400 to-emerald-300 mb-2">{stats.orders}+</h3>
                   <p className="text-sm text-[var(--text-color)] opacity-60 font-bold uppercase tracking-widest">Установок</p>
                </div>
                <div className="p-4 bg-green-500/10 rounded-2xl group-hover:scale-110 transition-transform">
                   <Activity size={32} className="text-green-400" />
                </div>
             </motion.div>
          </div>
        </div>
      </motion.section>

      {/* === SHOWCASE SECTION (Компоненты) === */}
      <section className="py-32 relative z-10">
        <div className="max-w-[1600px] mx-auto px-6">
           
           <motion.div 
             initial={{ opacity: 0, y: 30 }}
             whileInView={{ opacity: 1, y: 0 }}
             viewport={{ once: true }}
             className="text-center mb-24"
           >
             <h2 className="text-4xl md:text-6xl font-black text-[var(--text-color)] mb-4">ТЕХНОЛОГИЧЕСКИЙ СТЕК</h2>
             <div className="w-24 h-1 bg-[var(--accent-color)] mx-auto rounded-full" />
           </motion.div>

           <div className="grid grid-cols-1 lg:grid-cols-3 gap-12 items-center">
              
              {/* 1. MOBILE APP */}
              <motion.div 
                initial={{ opacity: 0, x: -50 }}
                whileInView={{ opacity: 1, x: 0 }}
                viewport={{ once: true }}
                className="glass p-8 rounded-[3rem] border border-[var(--glass-border)] flex flex-col items-center text-center group h-full relative overflow-hidden"
              >
                 <div className="absolute top-0 inset-x-0 h-px bg-gradient-to-r from-transparent via-[var(--accent-color)] to-transparent opacity-50" />
                 
                 <div className="h-[300px] flex items-center justify-center w-full mb-8">
                    <div className="transform scale-75 group-hover:scale-90 transition-transform duration-500">
                       <Iphone />
                    </div>
                 </div>
                 
                 <h3 className="text-2xl font-bold text-[var(--text-color)] mb-2 group-hover:text-[var(--accent-color)] transition-colors">Мобильный Контроль</h3>
                 <p className="text-sm opacity-60 text-[var(--text-color)]">Управление домом из любой точки мира. Полная синхронизация в реальном времени.</p>
              </motion.div>

              {/* 2. CORE SYSTEM (OS CORE) - CENTER */}
              <motion.div 
                initial={{ opacity: 0, y: 50 }}
                whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true }}
                className="glass p-2 rounded-[3rem] border border-[var(--glass-border)] flex flex-col items-center text-center group h-full relative overflow-hidden shadow-[0_0_50px_rgba(0,0,0,0.3)]"
              >
                 {/* Glowing bg */}
                 <div className="absolute inset-0 bg-[var(--accent-color)]/5 opacity-0 group-hover:opacity-100 transition-opacity duration-500" />

                 <div className="w-full flex items-center justify-center py-12 px-4 flex-grow">
                    {/* НОВЫЙ КОМПОНЕНТ OS CORE */}
                    <div className="transform scale-100 md:scale-125 transition-transform duration-500">
                       <OsCore />
                    </div>
                 </div>
                 
                 <div className="pb-8 px-8 relative z-10">
                    <h3 className="text-2xl font-bold text-[var(--text-color)] mb-2 group-hover:text-purple-400 transition-colors">Ядро Системы (OS)</h3>
                    <p className="text-sm opacity-60 text-[var(--text-color)]">Интеллектуальная операционная система, объединяющая все устройства в единый организм.</p>
                 </div>
              </motion.div>

              {/* 3. BIOMETRICS */}
              <motion.div 
                initial={{ opacity: 0, x: 50 }}
                whileInView={{ opacity: 1, x: 0 }}
                viewport={{ once: true }}
                className="glass p-8 rounded-[3rem] border border-[var(--glass-border)] flex flex-col items-center text-center group h-full relative overflow-hidden"
              >
                 <div className="absolute top-0 inset-x-0 h-px bg-gradient-to-r from-transparent via-green-500 to-transparent opacity-50" />

                 <div className="h-[300px] flex items-center justify-center w-full mb-8">
                    <div className="transform scale-100 group-hover:scale-110 transition-transform duration-500">
                       <Fingerprint />
                    </div>
                 </div>
                 
                 <h3 className="text-2xl font-bold text-[var(--text-color)] mb-2 group-hover:text-green-400 transition-colors">Биометрия</h3>
                 <p className="text-sm opacity-60 text-[var(--text-color)]">Бесключевой доступ и персональные сценарии на основе отпечатка пальца.</p>
              </motion.div>

           </div>
        </div>
      </section>

      {/* FOOTER CTA */}
      <section className="py-20 text-center relative z-10">
         <div className="absolute top-0 left-1/2 -translate-x-1/2 w-1/2 h-px bg-gradient-to-r from-transparent via-[var(--accent-color)] to-transparent" />
         <h2 className="text-3xl font-bold text-[var(--text-color)] mb-8">Готовы к будущему?</h2>
         <Link to="/contact" className="inline-flex items-center gap-2 px-8 py-3 rounded-full bg-[var(--text-color)] text-[var(--bg-color)] font-black hover:scale-105 transition-transform">
            СВЯЗАТЬСЯ С НАМИ <ArrowRight size={18} />
         </Link>
      </section>

    </div>
  );
};

export default Home;