import { useState, useEffect } from 'react';
import axios from 'axios';
import { ShoppingCart, History, Trash2, Plus, Minus, ArrowLeft, ArrowRight, Package, Cpu, ChevronLeft, ChevronRight, Filter } from 'lucide-react';
import { useNavigate } from 'react-router-dom';
import { motion, AnimatePresence } from 'framer-motion';
import Status from '../components/Status';

const categories = ['Все', 'Датчики', 'Камеры', 'Освещение', 'Хабы', 'Климат', 'Питание'];

const Dashboard = ({ user }) => {
  // Данные
  const [items, setItems] = useState([]);
  const [cart, setCart] = useState([]);
  const [orders, setOrders] = useState([]);
  
  // Состояния интерфейса
  const [loading, setLoading] = useState(true);
  const [selectedCat, setSelectedCat] = useState('Все');
  const [currentPage, setCurrentPage] = useState(1);
  const [isPaused, setIsPaused] = useState(false); // Пауза карусели
  const [orderIndex, setOrderIndex] = useState(0); // Индекс карусели

  const itemsPerPage = 9;
  const navigate = useNavigate();
  
  // ЗАГРУЗКА ДАННЫХ
  useEffect(() => {
    const fetchData = async () => {
      try {
        const token = localStorage.getItem('token');
        const [prodRes, orderRes] = await Promise.all([
          axios.get('https://test.apt142.ru/products'),
          axios.get('https://test.apt142.ru/orders', { headers: { Authorization: `Bearer ${token}` } })
        ]);
        setItems(prodRes.data);
        setOrders(orderRes.data);
        setCart(JSON.parse(localStorage.getItem('cart') || '[]'));
      } catch (e) { console.error(e); } finally { setLoading(false); }
    };
    fetchData();
  }, []);

  // Сохранение корзины
  useEffect(() => {
    localStorage.setItem('cart', JSON.stringify(cart));
  }, [cart]);

  // Сброс страницы при смене категории
  useEffect(() => {
    setCurrentPage(1);
  }, [selectedCat]);

  // === ЛОГИКА КАРУСЕЛИ (ЛОГ) ===
  useEffect(() => {
    // Крутим только если заказов больше 5 и нет паузы
    if (orders.length <= 5 || isPaused) return; 
    
    const interval = setInterval(() => {
      setOrderIndex((prev) => (prev + 1) % orders.length);
    }, 2000); // Скорость: 2 секунды
    
    return () => clearInterval(interval);
  }, [orders, isPaused]);

  const nextOrder = () => setOrderIndex((prev) => (prev + 1) % orders.length);
  const prevOrder = () => setOrderIndex((prev) => (prev - 1 + orders.length) % orders.length);

  // Получение 5 видимых заказов (циклически)
  const getVisibleOrders = () => {
    if (orders.length === 0) return [];
    if (orders.length < 5) return orders; // Если мало заказов, показываем сколько есть
    
    const result = [];
    for (let i = 0; i < 5; i++) {
      result.push(orders[(orderIndex + i) % orders.length]);
    }
    return result;
  };
  const visibleOrders = getVisibleOrders();

  // === ЛОГИКА КОРЗИНЫ ===
  const addToCart = (item) => {
    setCart(prev => {
      const exist = prev.find(i => i.id === item.id);
      return exist ? prev.map(i => i.id === item.id ? {...i, qty: i.qty + 1} : i) : [...prev, {...item, qty: 1}];
    });
  };

  const removeFromCart = (id) => setCart(prev => prev.filter(i => i.id !== id));

  const updateQty = (id, delta) => {
    setCart(prev => prev.map(i => {
      if (i.id === id) return { ...i, qty: Math.max(1, i.qty + delta) };
      return i;
    }));
  };

  const handlePayment = () => {
    if(cart.length === 0) return;
    localStorage.setItem('tempCart', JSON.stringify(cart));
    navigate('/payment');
  };

  // === ЛОГИКА ПАГИНАЦИИ И ФИЛЬТРОВ ===
  const filteredItems = selectedCat === 'Все' ? items : items.filter(i => i.category === selectedCat);
  const totalPages = Math.ceil(filteredItems.length / itemsPerPage);
  const currentItems = filteredItems.slice(
    (currentPage - 1) * itemsPerPage, 
    currentPage * itemsPerPage
  );

  if (loading) return (
    <div className="h-screen flex flex-col items-center justify-center gap-4">
       <div className="w-16 h-16 border-4 border-[var(--accent-color)] border-t-transparent rounded-full animate-spin"/>
       <span className="text-[var(--accent-color)] font-mono text-xl animate-pulse">ИНИЦИАЛИЗАЦИЯ СИСТЕМЫ...</span>
    </div>
  );

  return (
    <div className="flex flex-col gap-12 pb-20 max-w-[1900px] mx-auto min-h-screen px-4">
      
      {/* === HEADER & FILTERS === */}
      <motion.div 
        initial={{ y: -20, opacity: 0 }} animate={{ y: 0, opacity: 1 }}
        className="flex flex-col xl:flex-row justify-between items-end border-b border-[var(--glass-border)] pb-8 mt-8 gap-6"
      >
        <div>
          <h1 className="text-5xl font-black text-[var(--text-color)] mb-2 uppercase tracking-tighter">
            ТЕРМИНАЛ <span className="text-transparent bg-clip-text bg-gradient-to-r from-[var(--accent-color)] to-purple-600">NEXUS</span>
          </h1>
          <p className="text-[var(--text-color)] opacity-60 font-mono text-sm">
            :: OPERATOR: {user?.name.toUpperCase()} :: STATUS: ACTIVE
          </p>
        </div>

        {/* Категории */}
        <div className="flex flex-wrap gap-2">
          {categories.map(cat => (
            <button 
              key={cat}
              onClick={() => setSelectedCat(cat)}
              className={`px-5 py-2 rounded-xl font-bold text-xs uppercase tracking-widest transition-all border ${
                selectedCat === cat 
                ? 'bg-[var(--accent-color)] text-black border-[var(--accent-color)] shadow-[0_0_15px_var(--accent-color)]' 
                : 'glass text-[var(--text-color)] hover:bg-[var(--input-bg)] border-[var(--glass-border)]'
              }`}
            >
              {cat}
            </button>
          ))}
        </div>
      </motion.div>
      
      <div className="flex flex-col xl:flex-row gap-8 relative items-start">
        
        {/* === КАТАЛОГ ТОВАРОВ === */}
        <div className="flex-1 w-full">
          <div className="grid grid-cols-1 md:grid-cols-2 2xl:grid-cols-3 gap-6 mb-12">
            <AnimatePresence mode='wait'>
              {currentItems.map((item) => (
                <motion.div 
                  key={item.id}
                  initial={{ opacity: 0, scale: 0.9 }} animate={{ opacity: 1, scale: 1 }} exit={{ opacity: 0, scale: 0.9 }}
                  layout
                  className="uiverse-card group h-[380px] w-full border border-[var(--glass-border)] hover:border-[var(--accent-color)]/30 transition-colors"
                >
                  <div className="uiverse-card-content p-5 flex flex-col h-full justify-between bg-[var(--card-bg)]">
                    
                    {/* Картинка */}
                    <div className="relative h-48 w-full rounded-2xl overflow-hidden border border-[var(--glass-border)] bg-white p-4 group-hover:shadow-[0_0_20px_rgba(var(--accent-color),0.2)] transition-all">
                      <img 
                        src={item.image.startsWith('http') ? item.image : `https://test.apt142.ru/${item.image}`} 
                        className="w-full h-full object-contain group-hover:scale-110 transition-transform duration-500" 
                        alt={item.name} 
                      />
                      <div className="absolute top-2 left-2 bg-black/80 px-2 py-1 rounded text-[10px] text-white font-bold uppercase backdrop-blur-md">
                        {item.category}
                      </div>
                      <div className="absolute top-3 right-3 bg-black/80 px-3 py-1 rounded-lg text-[var(--accent-color)] font-bold font-mono border border-[var(--accent-color)]/30">
                        {item.price} ₽
                      </div>
                    </div>

                    {/* Описание */}
                    <div className="mt-4">
                       <h3 className="font-black text-lg text-[var(--text-color)] uppercase leading-none truncate" title={item.name}>{item.name}</h3>
                       <p className="text-xs text-[var(--text-color)] opacity-50 mt-2 line-clamp-2 h-8">{item.description}</p>
                    </div>

                    {/* Кнопка */}
                    <button 
                      onClick={() => addToCart(item)}
                      className="mt-4 w-full py-3 rounded-xl bg-[var(--accent-color)]/10 text-[var(--accent-color)] font-bold text-xs tracking-[0.2em] border border-[var(--accent-color)]/20 hover:bg-[var(--accent-color)] hover:text-black transition-all flex items-center justify-center gap-2 active:scale-95"
                    >
                      {cart.some(c => c.id === item.id) ? 'В ХРАНИЛИЩЕ' : 'ИНТЕГРИРОВАТЬ'} <Plus size={14} /> 
                    </button>
                  </div>
                </motion.div>
              ))}
            </AnimatePresence>
          </div>

          {/* ПАГИНАЦИЯ */}
          {totalPages > 1 && (
            <div className="flex justify-center gap-2 items-center mb-8">
              <button onClick={() => setCurrentPage(p => Math.max(1, p - 1))} disabled={currentPage === 1} className="p-2 rounded-lg glass hover:bg-[var(--accent-color)] hover:text-black transition-all disabled:opacity-30"><ArrowLeft size={20}/></button>
              
              {Array.from({ length: totalPages }).map((_, i) => (
                <button
                  key={i}
                  onClick={() => setCurrentPage(i + 1)}
                  className={`w-10 h-10 rounded-lg font-bold font-mono transition-all ${currentPage === i + 1 ? 'bg-[var(--accent-color)] text-black shadow-[0_0_15px_var(--accent-color)]' : 'glass hover:bg-white/10'}`}
                >
                  {i + 1}
                </button>
              ))}

              <button onClick={() => setCurrentPage(p => Math.min(totalPages, p + 1))} disabled={currentPage === totalPages} className="p-2 rounded-lg glass hover:bg-[var(--accent-color)] hover:text-black transition-all disabled:opacity-30"><ArrowRight size={20}/></button>
            </div>
          )}
        </div>

        {/* === КОРЗИНА (STICKY) === */}
        <div className="w-full xl:w-[400px] shrink-0">
          <div className="glass p-6 rounded-[2rem] sticky top-28 border border-[var(--glass-border)] shadow-2xl">
            <div className="flex justify-between items-center mb-6 pb-4 border-b border-[var(--glass-border)]">
              <h3 className="text-xl font-black text-[var(--text-color)] flex items-center gap-3 tracking-wider">
                <ShoppingCart size={20} className="text-[var(--accent-color)]" /> ХРАНИЛИЩЕ
              </h3>
              <span className="text-xs font-mono bg-[var(--bg-color)] px-2 py-1 rounded text-[var(--text-color)] opacity-50 border border-[var(--glass-border)]">
                {cart.length} МОД.
              </span>
            </div>
            
            <div className="flex flex-col gap-3 mb-6 max-h-[400px] overflow-y-auto pr-1 custom-scroll">
              {cart.length === 0 ? (
                <div className="text-center py-12 opacity-30 flex flex-col items-center border-2 border-dashed border-[var(--glass-border)] rounded-xl">
                   <Package size={40} className="mb-2" />
                   <p className="font-mono text-xs">НЕТ МОДУЛЕЙ</p>
                </div>
              ) : cart.map(c => (
                <div key={c.id} className="flex gap-3 items-center bg-[var(--input-bg)] p-3 rounded-xl border border-[var(--glass-border)] hover:border-[var(--accent-color)]/30 transition-colors">
                  <img src={c.image.startsWith('http') ? c.image : `https://test.apt142.ru/${c.image}`} className="w-12 h-12 rounded bg-white object-contain" />
                  <div className="flex-1 min-w-0">
                    <span className="text-xs font-bold block text-[var(--text-color)] truncate">{c.name}</span>
                    <span className="text-xs text-[var(--accent-color)] font-mono">{c.price * c.qty}₽</span>
                  </div>
                  <div className="flex flex-col items-end gap-1">
                    <button onClick={() => removeFromCart(c.id)} className="text-gray-500 hover:text-red-500"><Trash2 size={14}/></button>
                    <div className="flex items-center gap-1 bg-[var(--bg-color)] rounded-md p-0.5">
                      <button onClick={() => updateQty(c.id, -1)} className="p-0.5 hover:text-[var(--accent-color)]"><Minus size={10}/></button>
                      <span className="font-mono text-[10px] font-bold w-4 text-center">{c.qty}</span>
                      <button onClick={() => updateQty(c.id, 1)} className="p-0.5 hover:text-[var(--accent-color)]"><Plus size={10}/></button>
                    </div>
                  </div>
                </div>
              ))}
            </div>

            <div className="border-t border-[var(--glass-border)] pt-4">
              <div className="flex justify-between mb-4">
                <span className="text-[var(--text-color)] opacity-60 font-bold text-xs uppercase">Итого к оплате</span>
                <span className="text-xl font-black text-[var(--accent-color)] font-mono">
                  {cart.reduce((a, c) => a + c.price * c.qty, 0)}₽
                </span>
              </div>
              <button 
                onClick={handlePayment} 
                disabled={cart.length === 0} 
                className="w-full py-4 btn-neon text-white font-black tracking-[0.2em] rounded-xl disabled:opacity-50 disabled:cursor-not-allowed shadow-[0_0_20px_rgba(var(--accent-color),0.3)] hover:shadow-[0_0_30px_rgba(var(--accent-color),0.5)] flex justify-center items-center gap-3 transition-all active:scale-95"
              >
                <Cpu size={18} />
                ИНИЦИАЛИЗАЦИЯ
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* === ИСТОРИЯ ЗАКАЗОВ (5 БЛОКОВ, ПОЛНАЯ ШИРИНА) === */}
      {orders.length > 0 && (
        <div 
          className="mt-12 border-t border-[var(--glass-border)] pt-10"
          onMouseEnter={() => setIsPaused(true)}
          onMouseLeave={() => setIsPaused(false)}
        >
          <div className="flex justify-between items-center mb-6 px-4">
            <h3 className="text-3xl font-black text-[var(--text-color)] flex items-center gap-3 uppercase tracking-wider">
              <History className="text-[var(--accent-color)]" size={32} /> ЛОГ ОПЕРАЦИЙ
            </h3>
            
            {/* Навигация */}
            <div className="flex gap-2">
              <button onClick={prevOrder} className="p-3 rounded-xl bg-[var(--input-bg)] border border-[var(--glass-border)] hover:border-[var(--accent-color)] hover:text-[var(--accent-color)] transition-all active:scale-90"><ChevronLeft size={24} /></button>
              <button onClick={nextOrder} className="p-3 rounded-xl bg-[var(--input-bg)] border border-[var(--glass-border)] hover:border-[var(--accent-color)] hover:text-[var(--accent-color)] transition-all active:scale-90"><ChevronRight size={24} /></button>
            </div>
          </div>
          
          {/* КОНТЕЙНЕР КАРУСЕЛИ */}
          <div className="relative w-full overflow-hidden py-4">
             {/* Градиенты по бокам */}
             <div className="absolute left-0 top-0 w-24 h-full bg-gradient-to-r from-[var(--bg-color)] to-transparent z-10 pointer-events-none" />
             <div className="absolute right-0 top-0 w-24 h-full bg-gradient-to-l from-[var(--bg-color)] to-transparent z-10 pointer-events-none" />
             
             {/* GRID 5 КОЛОНОК */}
             <div className="grid grid-cols-1 md:grid-cols-3 xl:grid-cols-5 gap-6 px-4">
               <AnimatePresence mode='popLayout'>
                 {visibleOrders.map((order, i) => (
                   <motion.div 
                     key={`${order.id}-${orderIndex}-${i}`} 
                     initial={{ x: 100, opacity: 0 }}
                     animate={{ x: 0, opacity: 1 }}
                     exit={{ x: -100, opacity: 0 }}
                     transition={{ duration: 0.4, ease: "easeInOut" }}
                     className="glass p-5 rounded-3xl border border-[var(--glass-border)] relative overflow-hidden group min-h-[220px] flex flex-col justify-between hover:border-[var(--accent-color)]/30 transition-colors bg-[var(--card-bg)]/50"
                   >
                      {/* Индикатор статуса */}
                      <div className={`absolute top-0 left-0 w-1.5 h-full ${order.status === 'completed' ? 'bg-green-500 shadow-[0_0_10px_#22c55e]' : 'bg-blue-500 shadow-[0_0_10px_#3b82f6]'}`} />
                      
                      <div>
                        <div className="flex justify-between items-start mb-4">
                          <span className="font-mono text-[10px] px-2 py-1 rounded bg-[var(--accent-color)]/10 text-[var(--accent-color)] border border-[var(--accent-color)]/20">
                            #{order.order_number}
                          </span>
                          <span className="font-bold text-lg text-[var(--text-color)]">{order.total}₽</span>
                        </div>
                        
                        <p className="text-xs text-[var(--text-color)] opacity-70 font-bold leading-relaxed mb-4 line-clamp-3">
                          {order.subject || 'Системный заказ оборудования Nexus'}
                        </p>
                      </div>
                      
                      <div className="w-full mt-auto">
                        <Status status={order.status} date={new Date(order.created_at || order.date).toLocaleDateString()} />
                      </div>
                   </motion.div>
                 ))}
               </AnimatePresence>
             </div>
          </div>
        </div>
      )}

    </div>
  );
};

export default Dashboard;