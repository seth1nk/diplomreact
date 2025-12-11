import { useState, useEffect, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import axios from 'axios';
import { CreditCard, MapPin, Calendar, User, Phone, Navigation, Loader2 } from 'lucide-react';
import { motion } from 'framer-motion';
import Iphone from '../components/Iphone'; 

const Payment = () => {
  const [cart, setCart] = useState([]);
  const [loading, setLoading] = useState(false);
  
  // Состояние формы
  const [form, setForm] = useState({
    fio: '',
    phone: '',
    address: '',
    date: '',
    coords: '52.5400, 103.8800'
  });

  const mapInstance = useRef(null); 
  const navigate = useNavigate();

  // 1. ЗАГРУЗКА КОРЗИНЫ
  useEffect(() => {
    const savedCart = JSON.parse(localStorage.getItem('tempCart') || '[]');
    setCart(savedCart);
    if(savedCart.length === 0) navigate('/dashboard');
  }, []);

  const total = cart.reduce((acc, item) => acc + item.price * item.qty, 0);

  // 2. ИНИЦИАЛИЗАЦИЯ КАРТЫ
  useEffect(() => {
    if (!window.ymaps) {
      const script = document.createElement('script');
      script.src = "https://api-maps.yandex.ru/2.1/?apikey=794e6377-6202-426f-8706-930263f350df&lang=ru_RU";
      script.async = true;
      document.body.appendChild(script);
      script.onload = initMap;
    } else {
      initMap();
    }

    return () => {
        if (mapInstance.current) {
            mapInstance.current = null;
        }
    };
  }, []);

  const initMap = () => {
    window.ymaps.ready(() => {
      if (mapInstance.current) return;

      const map = new window.ymaps.Map("yandex-map", {
        center: [52.5400, 103.8800], // Ангарск
        zoom: 13,
        controls: ['zoomControl']
      });

      mapInstance.current = map;

      const myPlacemark = new window.ymaps.Placemark([52.5400, 103.8800], {
          hintContent: 'Место установки'
      }, {
          preset: 'islands#redDotIcon'
      });
      
      map.geoObjects.add(myPlacemark);

      map.events.add('click', function (e) {
        const coords = e.get('coords');
        myPlacemark.geometry.setCoordinates(coords);
        
        const lat = coords[0].toFixed(4);
        const lon = coords[1].toFixed(4);
        
        const streets = ['ул. Карла Маркса', 'ул. Ленина', '12-й микрорайон', '85-й квартал', 'ул. Космонавтов', 'ул. Чайковского', 'ул. Горького', 'мкр. Китова'];
        const randomStreet = streets[Math.floor(Math.random() * streets.length)];
        const randomHouse = Math.floor(Math.random() * 80) + 1;
        const detectedAddress = `г. Ангарск, ${randomStreet}, д. ${randomHouse}`;

        setForm(prev => ({ 
          ...prev, 
          coords: `${lat}, ${lon}`,
          address: detectedAddress 
        }));
      });
    });
  };

  // --- ЛОГИКА ОПЛАТЫ ---
  const handlePay = async (e) => {
    e.preventDefault();
    setLoading(true);

    try {
      const token = localStorage.getItem('token');
      
      // 1. СОЗДАЕМ ЗАКАЗ В БАЗЕ
      const res = await axios.post('https://test.apt142.ru/orders', {
        cart: cart,       
        delivery: form    
      }, { 
        headers: { Authorization: `Bearer ${token}` }
      });
      
      const orderId = res.data.orderId;

      if (!orderId) {
          alert('Ошибка сервера: не вернулся номер заказа.');
          setLoading(false);
          return;
      }
      
      // 2. ЧИСТИМ КОРЗИНУ
      localStorage.removeItem('cart');
      localStorage.removeItem('tempCart');

      // 3. ЖЕСТКИЙ РЕДИРЕКТ В ТЕЛЕГРАМ
      // Окно браузера сразу перейдет в ТГ
      window.location.href = `https://t.me/oplata_umniydombot?start=${orderId}`;

    } catch (e) {
      console.error(e);
      setLoading(false);
      alert('Ошибка при создании заказа.');
    }
  };

  return (
    <div className="pt-32 min-h-screen flex justify-center items-start px-4 pb-20 overflow-x-hidden">
      <div className="max-w-[1600px] w-full grid grid-cols-1 xl:grid-cols-12 gap-12 items-start">
        
        {/* ЛЕВАЯ КОЛОНКА */}
        <motion.div 
          initial={{ x: -50, opacity: 0 }} animate={{ x: 0, opacity: 1 }}
          className="xl:col-span-8 flex flex-col lg:flex-row gap-8"
        >
          <div className="hidden lg:flex flex-col items-center gap-6 pt-10 sticky top-32 h-fit">
             <div className="scale-90 xl:scale-100 hover:scale-105 transition-transform duration-500">
                <Iphone />
             </div>
             <p className="text-[var(--text-color)] opacity-40 text-xs font-mono text-center max-w-[200px]">
               Управляйте установкой через приложение Nexus Home после оплаты
             </p>
          </div>

          <div className="flex-1 glass p-8 md:p-10 rounded-[2.5rem] border border-[var(--glass-border)]">
            <div className="flex items-center gap-4 mb-8 border-b border-[var(--glass-border)] pb-6">
               <div className="p-3 bg-[var(--accent-color)]/10 rounded-2xl text-[var(--accent-color)] border border-[var(--accent-color)]/20">
                  <Navigation size={28} />
               </div>
               <div>
                 <h2 className="text-3xl font-black text-[var(--text-color)] uppercase tracking-tight">Настройка</h2>
                 <p className="text-[var(--text-color)] opacity-50 text-sm">Данные для выезда инженера</p>
               </div>
            </div>
            
            <form id="pay-form" onSubmit={handlePay} className="space-y-6">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                 <div className="group">
                   <label className="text-[10px] font-bold text-[var(--text-color)] opacity-50 ml-4 mb-1 block uppercase tracking-widest">ФИО Клиента</label>
                   <div className="relative">
                     <User className="absolute left-5 top-4 text-gray-500" size={18}/>
                     <input 
                       className="w-full bg-[var(--input-bg)] border border-[var(--glass-border)] rounded-2xl py-3.5 pl-12 pr-6 text-[var(--text-color)] outline-none focus:border-[var(--accent-color)] transition-all font-bold"
                       placeholder="Иванов Иван" required 
                       value={form.fio} onChange={e=>setForm({...form, fio: e.target.value})}
                     />
                   </div>
                 </div>
                 <div className="group">
                   <label className="text-[10px] font-bold text-[var(--text-color)] opacity-50 ml-4 mb-1 block uppercase tracking-widest">Телефон</label>
                   <div className="relative">
                     <Phone className="absolute left-5 top-4 text-gray-500" size={18}/>
                     <input 
                       className="w-full bg-[var(--input-bg)] border border-[var(--glass-border)] rounded-2xl py-3.5 pl-12 pr-6 text-[var(--text-color)] outline-none focus:border-[var(--accent-color)] transition-all font-mono"
                       placeholder="+7 (999)..." required 
                       value={form.phone} onChange={e=>setForm({...form, phone: e.target.value})}
                     />
                   </div>
                 </div>
              </div>

              <div className="group">
                 <label className="text-[10px] font-bold text-[var(--text-color)] opacity-50 ml-4 mb-1 block uppercase tracking-widest">Адрес (Кликните на карту)</label>
                 <div className="relative">
                   <MapPin className="absolute left-5 top-4 text-gray-500" size={18}/>
                   <input 
                     className="w-full bg-[var(--input-bg)] border border-[var(--glass-border)] rounded-2xl py-3.5 pl-12 pr-6 text-[var(--text-color)] outline-none focus:border-[var(--accent-color)] transition-all font-bold text-[var(--accent-color)]"
                     placeholder="Выберите точку на карте..." required 
                     value={form.address} onChange={e=>setForm({...form, address: e.target.value})}
                   />
                 </div>
              </div>

              <div className="group">
                 <label className="text-[10px] font-bold text-[var(--text-color)] opacity-50 ml-4 mb-1 block uppercase tracking-widest">Дата монтажа</label>
                 <div className="relative">
                   <Calendar className="absolute left-5 top-4 text-gray-500" size={18}/>
                   <input type="datetime-local" className="w-full bg-[var(--input-bg)] border border-[var(--glass-border)] rounded-2xl py-3.5 pl-12 pr-6 text-[var(--text-color)] outline-none focus:border-[var(--accent-color)] transition-all font-mono" required 
                     value={form.date} onChange={e=>setForm({...form, date: e.target.value})}
                   />
                 </div>
              </div>

              <div className="group pt-2">
                 <div className="flex justify-between items-end mb-2 ml-2">
                    <label className="text-[10px] font-bold text-[var(--text-color)] opacity-50 uppercase tracking-widest">Геолокация объекта</label>
                    <span className="text-[10px] font-mono text-[var(--accent-color)] bg-[var(--accent-color)]/10 px-2 py-0.5 rounded border border-[var(--accent-color)]/20">
                      {form.coords}
                    </span>
                 </div>
                 
                 <div className="h-80 w-full rounded-[2rem] overflow-hidden border border-[var(--glass-border)] shadow-inner relative bg-[var(--bg-color)]">
                    <div 
                        id="yandex-map" 
                        style={{ width: '100%', height: '100%', filter: 'var(--map-filter)' }}
                        className="transition-all duration-700" 
                    />
                 </div>
              </div>
            </form>
          </div>
        </motion.div>

        {/* ПРАВАЯ КОЛОНКА: ЧЕК */}
        <motion.div 
          initial={{ x: 50, opacity: 0 }} animate={{ x: 0, opacity: 1 }} transition={{ delay: 0.2 }}
          className="xl:col-span-4 h-fit sticky top-28"
        >
          <div className="glass p-8 rounded-[2.5rem] border border-[var(--glass-border)] shadow-2xl relative overflow-hidden">
             <div className="absolute top-0 right-0 w-32 h-32 bg-[var(--accent-color)]/20 blur-[60px] rounded-full pointer-events-none" />

             <h3 className="text-xl font-black text-[var(--text-color)] mb-6 flex items-center gap-2">
               <CreditCard className="text-[var(--accent-color)]"/> СВОДКА
             </h3>

             <div className="space-y-3 mb-8 max-h-[300px] overflow-y-auto pr-1 custom-scroll">
                {cart.map(item => (
                  <div key={item.id} className="flex justify-between items-center text-sm p-3 rounded-xl bg-[var(--bg-color)]/50 border border-[var(--glass-border)]">
                    <div className="flex items-center gap-3 overflow-hidden">
                       <div className="w-10 h-10 rounded-lg bg-white p-1 shrink-0">
                          <img src={item.image.startsWith('http') ? item.image : `https://test.apt142.ru/${item.image}`} className="w-full h-full object-contain" />
                       </div>
                       <div className="flex flex-col truncate">
                          <span className="font-bold text-[var(--text-color)] truncate">{item.name}</span>
                          <span className="text-[10px] opacity-60">x{item.qty}</span>
                       </div>
                    </div>
                    <span className="font-mono font-bold text-[var(--accent-color)]">{item.price * item.qty}₽</span>
                  </div>
                ))}
             </div>

             <div className="border-t border-[var(--glass-border)] pt-6 mb-8 space-y-2">
                <div className="flex justify-between text-sm opacity-60">
                   <span>Оборудование:</span>
                   <span className="font-mono">{total}₽</span>
                </div>
                <div className="flex justify-between text-sm opacity-60">
                   <span>Монтаж:</span>
                   <span className="font-mono text-green-400">БЕСПЛАТНО</span>
                </div>
                <div className="flex justify-between text-2xl font-black text-[var(--text-color)] mt-4">
                   <span>ИТОГО:</span>
                   <span className="text-[var(--accent-color)]">{total}₽</span>
                </div>
             </div>

             <button 
               form="pay-form" 
               disabled={loading}
               className="w-full py-5 btn-neon text-white font-black tracking-[0.15em] rounded-2xl flex items-center justify-center gap-3 shadow-[0_10px_30px_rgba(0,0,0,0.3)] hover:scale-[1.02] active:scale-[0.98] transition-all disabled:opacity-50 disabled:cursor-not-allowed"
             >
               {loading ? <><Loader2 className="animate-spin" /> ПЕРЕХОД...</> : 'ОПЛАТИТЬ ЧЕРЕЗ TELEGRAM'}
             </button>
             
             <div className="mt-6 flex justify-center gap-4 opacity-30 grayscale">
                <img src="https://upload.wikimedia.org/wikipedia/commons/2/2a/Mastercard-logo.svg" className="h-6" alt="MC"/>
                <img src="https://upload.wikimedia.org/wikipedia/commons/5/5e/Visa_Inc._logo.svg" className="h-6" alt="Visa"/>
             </div>
          </div>
        </motion.div>

      </div>
    </div>
  );
};

export default Payment;