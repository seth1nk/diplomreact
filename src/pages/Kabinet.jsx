import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { motion } from 'framer-motion';
import { 
  User, Calendar, Shield, Key, Lock, 
  Package, Clock, CheckCircle, Truck, XCircle, Send, ExternalLink 
} from 'lucide-react';
import UserAvatar from '../components/UserAvatar';

const API_URL = 'https://test.apt142.ru';

const Kabinet = ({ user }) => {
  const [orders, setOrders] = useState([]);
  const [loading, setLoading] = useState(true);
  const [passForm, setPassForm] = useState({ oldPassword: '', newPassword: '' });
  const [passMsg, setPassMsg] = useState('');
  const [passError, setPassError] = useState('');
  const [telegramInfo, setTelegramInfo] = useState(null);

  useEffect(() => {
    if (user) {
        fetchUserOrders();
    }
  }, [user]);

  const fetchUserOrders = async () => {
    try {
      const token = localStorage.getItem('token');
      // Запрашиваем /orders. После исправления index.js придут только заказы этого юзера
      const res = await axios.get(`${API_URL}/orders`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      const userOrders = res.data;
      setOrders(userOrders);

      // Ищем привязанный TG (проверяем, есть ли хоть в одном заказе telegram_chat_id)
      const linkedOrder = userOrders.find(o => o.telegram_chat_id);
      if (linkedOrder) {
        setTelegramInfo({
            id: linkedOrder.telegram_chat_id,
            username: linkedOrder.telegram_username || user.name,
            connected: true
        });
      }
    } catch (e) { 
        console.error("Ошибка загрузки заказов:", e); 
    } finally { 
        setLoading(false); 
    }
  };

  const handleChangePassword = async (e) => {
    e.preventDefault();
    setPassMsg(''); setPassError('');
    if (passForm.newPassword.length < 6) return setPassError('Мин. 6 символов');
    try {
      const token = localStorage.getItem('token');
      await axios.put(`${API_URL}/users/password`, passForm, { headers: { Authorization: `Bearer ${token}` } });
      setPassMsg('Пароль обновлен!'); setPassForm({ oldPassword: '', newPassword: '' });
    } catch (e) { setPassError(e.response?.data?.error || 'Ошибка смены пароля'); }
  };

  const handleCancelOrder = async (orderId) => {
    if (!window.confirm('Вы уверены, что хотите отменить заказ?')) return;
    try {
      await axios.post(`${API_URL}/api/internal/orders/${orderId}/cancel-by-user`);
      // Обновляем список локально, чтобы не дергать сервер лишний раз (или можно вызвать fetchUserOrders)
      setOrders(orders.map(o => o.id === orderId ? { ...o, status: 'cancelled' } : o));
      alert('Заказ отменен.');
    } catch (e) { alert('Не удалось отменить.'); }
  };

  const getStatusBadge = (status) => {
    switch (status) {
      case 'placed': return <span className="flex items-center gap-1 text-blue-400 bg-blue-400/10 px-2 py-1 rounded text-xs border border-blue-400/20"><Clock size={12}/> РАЗМЕЩЕН</span>;
      case 'processing': return <span className="flex items-center gap-1 text-yellow-400 bg-yellow-400/10 px-2 py-1 rounded text-xs border border-yellow-400/20"><Package size={12}/> В РАБОТЕ</span>;
      case 'shipped': return <span className="flex items-center gap-1 text-purple-400 bg-purple-400/10 px-2 py-1 rounded text-xs border border-purple-400/20"><Truck size={12}/> В ПУТИ</span>;
      case 'completed': return <span className="flex items-center gap-1 text-green-400 bg-green-400/10 px-2 py-1 rounded text-xs border border-green-400/20"><CheckCircle size={12}/> ВЫПОЛНЕН</span>;
      case 'cancelled': return <span className="flex items-center gap-1 text-red-400 bg-red-400/10 px-2 py-1 rounded text-xs border border-red-400/20"><XCircle size={12}/> ОТМЕНЕН</span>;
      default: return <span className="opacity-50">{status}</span>;
    }
  };

  if (!user) return <div className="pt-32 text-center text-white">Загрузка профиля...</div>;

  return (
    <div className="pt-28 pb-10 min-h-screen px-4 max-w-7xl mx-auto">
      <motion.h1 initial={{ opacity: 0, x: -20 }} animate={{ opacity: 1, x: 0 }} className="text-4xl font-black text-[var(--accent-color)] mb-8 uppercase tracking-widest">
        Личный Кабинет
      </motion.h1>
      
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
        
        {/* ЛЕВАЯ КОЛОНКА: ПРОФИЛЬ */}
        <div className="lg:col-span-1 space-y-6">
          
          {/* КАРТОЧКА ПОЛЬЗОВАТЕЛЯ */}
          <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} className="glass p-6 rounded-2xl border border-[var(--glass-border)] shadow-xl relative overflow-hidden">
            <div className="absolute top-0 left-0 w-full h-20 bg-[var(--accent-color)]/10" />
            <div className="relative z-10 flex flex-col items-center">
               <div className="p-1 bg-[var(--bg-color)] rounded-full mb-4">
                  <UserAvatar user={user} className="w-24 h-24 rounded-full border-2 border-[var(--accent-color)]" />
               </div>
               <h2 className="text-2xl font-bold text-[var(--text-color)]">{user.name}</h2>
               <p className="text-sm opacity-50 mb-6 font-mono">{user.email}</p>
               
               <div className="w-full space-y-3">
                  <div className="flex items-center gap-3 p-3 bg-[var(--input-bg)] rounded-xl border border-[var(--glass-border)]">
                      <Shield size={18} className="text-[var(--accent-color)]"/>
                      <div className="text-xs">
                          <p className="opacity-50">Роль</p>
                          <p className="font-bold uppercase">{user.role}</p>
                      </div>
                  </div>
                  <div className="flex items-center gap-3 p-3 bg-[var(--input-bg)] rounded-xl border border-[var(--glass-border)]">
                      <Calendar size={18} className="text-[var(--accent-color)]"/>
                      <div className="text-xs">
                          <p className="opacity-50">Дата регистрации</p>
                          <p>{user.created_at ? new Date(user.created_at).toLocaleDateString() : '-'}</p>
                      </div>
                  </div>
               </div>
            </div>
          </motion.div>

          {/* TELEGRAM */}
          <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.15 }} className="glass p-6 rounded-2xl border border-[var(--glass-border)] shadow-xl">
             <h3 className="text-lg font-bold text-[var(--text-color)] mb-4 flex items-center gap-2"><Send size={18} className="text-blue-400"/> TELEGRAM</h3>
            {telegramInfo ? (
                <div className="bg-blue-500/10 border border-blue-500/30 rounded-xl p-4">
                    <div className="flex items-center gap-4">
                        <div className="w-12 h-12 rounded-full bg-blue-500 flex items-center justify-center text-white font-bold text-xl">
                            {telegramInfo.username[0].toUpperCase()}
                        </div>
                        <div className="overflow-hidden">
                            <p className="text-sm font-bold text-white truncate">{telegramInfo.username}</p>
                            <p className="text-[10px] text-blue-300 font-mono">ID: {telegramInfo.id}</p>
                            <a href={`https://t.me/${telegramInfo.username}`} target="_blank" rel="noreferrer" className="text-[10px] text-blue-400 hover:text-white flex items-center gap-1 mt-1">@{telegramInfo.username} <ExternalLink size={8}/></a>
                        </div>
                    </div>
                    <div className="mt-3 text-[10px] text-center bg-blue-500/20 py-1 rounded text-blue-200">✅ Аккаунт привязан</div>
                </div>
            ) : (
                <div className="text-center p-4 bg-[var(--input-bg)] rounded-xl border border-dashed border-gray-600">
                    <p className="text-sm opacity-50 mb-2">Аккаунт не привязан</p>
                    <p className="text-xs opacity-30">Совершите покупку через бота, чтобы привязать уведомления.</p>
                </div>
            )}
          </motion.div>

          {/* СМЕНА ПАРОЛЯ */}
          <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.2 }} className="glass p-6 rounded-2xl border border-[var(--glass-border)] shadow-xl">
            <h3 className="text-lg font-bold text-[var(--text-color)] mb-4 flex items-center gap-2"><Key size={18} className="text-[var(--accent-color)]"/> ПАРОЛЬ</h3>
            <form onSubmit={handleChangePassword} className="space-y-3">
               <div className="relative">
                   <Lock size={14} className="absolute left-3 top-3 opacity-30"/>
                   <input type="password" placeholder="Старый пароль" className="w-full bg-[var(--input-bg)] border border-[var(--glass-border)] rounded-lg py-2 pl-9 pr-3 text-sm text-[var(--text-color)] outline-none focus:border-[var(--accent-color)]" value={passForm.oldPassword} onChange={e => setPassForm({...passForm, oldPassword: e.target.value})} required/>
               </div>
               <div className="relative">
                   <Key size={14} className="absolute left-3 top-3 opacity-30"/>
                   <input type="password" placeholder="Новый пароль" className="w-full bg-[var(--input-bg)] border border-[var(--glass-border)] rounded-lg py-2 pl-9 pr-3 text-sm text-[var(--text-color)] outline-none focus:border-[var(--accent-color)]" value={passForm.newPassword} onChange={e => setPassForm({...passForm, newPassword: e.target.value})} required/>
               </div>
               {passMsg && <p className="text-xs text-green-500 text-center">{passMsg}</p>}
               {passError && <p className="text-xs text-red-500 text-center">{passError}</p>}
               <button className="w-full btn-neon py-2 rounded-lg text-xs font-bold mt-2 hover:scale-105 transition-transform">ОБНОВИТЬ</button>
            </form>
          </motion.div>
        </div>

        {/* ПРАВАЯ КОЛОНКА: ЗАКАЗЫ */}
        <motion.div initial={{ opacity: 0, x: 20 }} animate={{ opacity: 1, x: 0 }} transition={{ delay: 0.3 }} className="lg:col-span-2">
           <div className="glass p-6 rounded-2xl border border-[var(--glass-border)] shadow-xl min-h-[600px]">
              <h3 className="text-2xl font-bold text-[var(--text-color)] mb-6 flex items-center gap-3"><Package className="text-[var(--accent-color)]"/> МОИ ЗАКАЗЫ</h3>
              
              {loading ? (
                  <div className="text-center opacity-50 py-20 animate-pulse">Загрузка списка заказов...</div>
              ) : orders.length === 0 ? (
                  <div className="text-center py-20 flex flex-col items-center">
                      <Package size={48} className="mx-auto opacity-20 mb-4"/>
                      <p className="opacity-50">История заказов пуста</p>
                  </div>
              ) : (
                 <div className="space-y-4">
                    {orders.map((o) => (
                       <div key={o.id} className="p-5 bg-[var(--input-bg)]/30 border border-[var(--glass-border)] rounded-2xl hover:border-[var(--accent-color)]/30 transition-all">
                          
                          {/* ХЕДЕР ЗАКАЗА */}
                          <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4 mb-4 border-b border-[var(--glass-border)] pb-4">
                             <div className="flex items-center gap-3">
                                <div className="w-10 h-10 rounded-full bg-[var(--bg-color)] flex items-center justify-center border border-[var(--glass-border)] text-[var(--accent-color)] font-bold">
                                    #{o.order_number || o.id}
                                </div>
                                <div>
                                    <div className="flex items-center gap-2">{getStatusBadge(o.status)}</div>
                                    <span className="text-[10px] opacity-40 font-mono block mt-1">{new Date(o.created_at).toLocaleString()}</span>
                                </div>
                             </div>
                             
                             {(o.status === 'placed' || o.status === 'processing') && (
                                <button onClick={() => handleCancelOrder(o.id)} className="flex items-center gap-1 text-[10px] text-red-400 bg-red-500/10 px-3 py-1.5 rounded-lg border border-red-500/20 hover:bg-red-500 hover:text-white transition-colors">
                                    <XCircle size={14}/> ОТМЕНИТЬ ЗАКАЗ
                                </button>
                             )}
                          </div>

                          {/* ТЕЛО ЗАКАЗА */}
                          <div className="flex flex-col md:flex-row gap-6">
                             <div className="flex-1">
                                <p className="text-[10px] uppercase opacity-40 mb-1 font-bold">Содержание</p>
                                <p className="text-sm text-[var(--text-color)] leading-relaxed font-medium">{o.content}</p>
                                
                                {o.delivery_address && (
                                    <div className="mt-3 flex gap-2">
                                        <div className="w-0.5 bg-[var(--glass-border)] self-stretch" />
                                        <p className="text-xs opacity-60 font-mono whitespace-pre-wrap">{o.delivery_address}</p>
                                    </div>
                                )}
                             </div>
                             
                             <div className="md:w-40 shrink-0 flex flex-col gap-2">
                                <div className="bg-[var(--bg-color)] p-3 rounded-xl border border-[var(--glass-border)]">
                                    <span className="text-[10px] opacity-50 block">Сумма</span>
                                    <span className="font-bold text-[var(--accent-color)] text-lg">{o.total} ₽</span>
                                </div>
                                <div className={`p-2 rounded-xl border text-center text-xs font-bold ${o.payment_status === 'paid' ? 'bg-green-500/10 text-green-500 border-green-500/20' : 'bg-yellow-500/10 text-yellow-500 border-yellow-500/20'}`}>
                                    {o.payment_status === 'paid' ? 'ОПЛАЧЕНО' : 'НЕ ОПЛАЧЕНО'}
                                </div>
                             </div>
                          </div>
                       </div>
                    ))}
                 </div>
              )}
           </div>
        </motion.div>
      </div>
    </div>
  );
};
export default Kabinet;