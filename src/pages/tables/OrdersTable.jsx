import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { 
  Eye, X, ChevronLeft, ChevronRight, 
  Package, Truck, CheckCircle, AlertTriangle, ArrowRight, XCircle, 
  Clock, RefreshCw, AlertCircle
} from 'lucide-react';

const API_URL = 'https://test.apt142.ru';

const OrdersTable = ({ user }) => {
  const [orders, setOrders] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [viewData, setViewData] = useState(null);
  
  // ПАГИНАЦИЯ
  const [currentPage, setCurrentPage] = useState(1);
  const itemsPerPage = 10;
  
  // Проверка прав (Админ или Спец. юзеры)
  const isAdmin = 
    user?.role === 'admin' || 
    user?.email === 'admin@mail.ru' || 
    user?.name === 'seth1nk';

  useEffect(() => {
    fetchOrders();
    const interval = setInterval(fetchOrders, 15000); // Автообновление
    return () => clearInterval(interval);
  }, [user]);

  const fetchOrders = async () => { 
    const token = localStorage.getItem('token');
    if (!token) return;

    try {
      setLoading(true);
      
      // --- ИЗМЕНЕНИЕ: ТЕПЕРЬ ВСЕ ИДУТ НА ОДИН РОУТ ---
      const endpoint = '/admin/orders'; 
      // -----------------------------------------------

      const res = await axios.get(`${API_URL}${endpoint}`, { 
        headers: { Authorization: `Bearer ${token}` } 
      }); 
      
      const sorted = res.data.sort((a, b) => new Date(b.created_at) - new Date(a.created_at));
      setOrders(sorted);
      setError(null);
    } catch(e) { 
      console.error(e);
      // Ошибки теперь обрабатываем мягче, так как роут один
      setError("Не удалось загрузить заказы");
    } finally {
      setLoading(false);
    }
  };

  // ==========================================
  // ЛОГИКА АДМИНА (УПРАВЛЕНИЕ)
  // ==========================================

  const advanceStatus = async (id, currentStatus) => {
    let nextStatus = '';
    if (currentStatus === 'processing') nextStatus = 'shipped'; // В пути
    else if (currentStatus === 'shipped') nextStatus = 'completed'; // Выполнен
    else return; // placed переводим вручную, либо добавь сюда case 'placed': nextStatus = 'processing'

    // Если статус 'placed' (новый), сначала переводим в 'processing' (в работу)
    if (currentStatus === 'placed') nextStatus = 'processing';

    if (!window.confirm(`Перевести заказ в статус "${nextStatus.toUpperCase()}"? Клиент получит уведомление.`)) return;

    try {
      await axios.put(`${API_URL}/admin/orders/${id}`, { status: nextStatus }, { 
        headers: { Authorization: `Bearer ${localStorage.getItem('token')}` } 
      });
      fetchOrders(); // Обновляем таблицу
    } catch(e) { alert('Ошибка обновления статуса'); }
  };

  const cancelOrder = async (id) => {
    if (!window.confirm('ОТМЕНИТЬ ЗАКАЗ?\n\nНажмите ОК для отмены. Статус сменится на CANCELLED.')) return;
    try {
      await axios.put(`${API_URL}/admin/orders/${id}`, { status: 'cancelled' }, { 
        headers: { Authorization: `Bearer ${localStorage.getItem('token')}` } 
      });
      fetchOrders();
    } catch(e) { alert('Ошибка отмены'); }
  };

  // --- РЕНДЕР: ПАЙПЛАЙН (Кружочки для Админа) ---
  const renderStatusPipeline = (status) => {
    if (status === 'cancelled') {
      return (
        <div className="flex items-center gap-2 text-red-500 bg-red-500/10 px-3 py-1.5 rounded border border-red-500/20 w-fit">
          <AlertTriangle size={14} /> <span className="text-[10px] font-bold uppercase tracking-widest">ОТМЕНЕН</span>
        </div>
      );
    }

    const steps = [
      { key: 'processing', icon: Package, label: 'В работе' },
      { key: 'shipped', icon: Truck, label: 'В пути' },
      { key: 'completed', icon: CheckCircle, label: 'Готов' }
    ];

    // Если статус 'placed', мы на "нулевом" шаге (перед первым)
    let activeIndex = -1;
    if (status === 'processing') activeIndex = 0;
    if (status === 'shipped') activeIndex = 1;
    if (status === 'completed') activeIndex = 2;

    return (
      <div className="flex items-center gap-1">
        {status === 'placed' && (
            <span className="text-[9px] font-bold bg-blue-500/20 text-blue-400 px-2 py-1 rounded border border-blue-500/30 mr-2">НОВЫЙ</span>
        )}
        {steps.map((step, idx) => {
          const isActive = idx === activeIndex;
          const isPassed = idx < activeIndex;
          
          let colorClass = 'text-gray-600 border-gray-700 bg-gray-800/50';
          if (isActive) colorClass = 'text-[var(--accent-color)] border-[var(--accent-color)] bg-[var(--accent-color)]/10 animate-pulse';
          if (isPassed) colorClass = 'text-green-500 border-green-500 bg-green-500/10';

          return (
            <div key={step.key} className="flex items-center">
              <div title={step.label} className={`w-7 h-7 flex items-center justify-center rounded-full border ${colorClass} transition-all duration-300 relative group`}>
                <step.icon size={12} />
              </div>
              {idx < steps.length - 1 && (
                <div className={`w-4 h-0.5 mx-0.5 ${isPassed ? 'bg-green-500' : 'bg-gray-800'}`} />
              )}
            </div>
          );
        })}
      </div>
    );
  };

  // ==========================================
  // ЛОГИКА ЮЗЕРА (ОБЫЧНЫЕ БЕЙДЖИ)
  // ==========================================
  const renderStatusBadge = (status) => {
    switch (status) {
      case 'placed': return <span className="flex items-center gap-1 text-[10px] font-bold text-blue-400 bg-blue-400/10 px-2 py-1 rounded border border-blue-400/20"><Clock size={12}/> НОВЫЙ</span>;
      case 'processing': return <span className="flex items-center gap-1 text-[10px] font-bold text-yellow-400 bg-yellow-400/10 px-2 py-1 rounded border border-yellow-400/20"><RefreshCw size={12}/> В РАБОТЕ</span>;
      case 'shipped': return <span className="flex items-center gap-1 text-[10px] font-bold text-purple-400 bg-purple-400/10 px-2 py-1 rounded border border-purple-400/20"><Truck size={12}/> ОТПРАВЛЕН</span>;
      case 'completed': return <span className="flex items-center gap-1 text-[10px] font-bold text-green-400 bg-green-400/10 px-2 py-1 rounded border border-green-400/20"><CheckCircle size={12}/> ВЫПОЛНЕН</span>;
      case 'cancelled': return <span className="flex items-center gap-1 text-[10px] font-bold text-red-400 bg-red-400/10 px-2 py-1 rounded border border-red-400/20"><XCircle size={12}/> ОТМЕНЕН</span>;
      default: return <span className="text-[10px] opacity-50">{status}</span>;
    }
  };

  // ==========================================
  // РЕНДЕР
  // ==========================================
  
  const indexOfLastItem = currentPage * itemsPerPage;
  const indexOfFirstItem = indexOfLastItem - itemsPerPage;
  const currentItems = orders.slice(indexOfFirstItem, indexOfLastItem);
  const totalPages = Math.ceil(orders.length / itemsPerPage);

  return (
    <div className="pt-28 pb-10 min-h-screen px-4">
      <div className="max-w-7xl mx-auto">
        
        {/* ЗАГОЛОВОК */}
        <div className="flex justify-between items-end mb-6 border-b border-[var(--glass-border)] pb-4">
           <div>
               <h2 className="text-3xl font-black text-[var(--accent-color)] uppercase tracking-widest">
                 {isAdmin ? `УПРАВЛЕНИЕ ЗАКАЗАМИ (${orders.length})` : `МОИ ЗАКАЗЫ (${orders.length})`}
               </h2>
           </div>
           <button onClick={fetchOrders} className="p-2 bg-[var(--accent-color)]/20 rounded hover:bg-[var(--accent-color)] hover:text-black transition-all">
               <RefreshCw size={18} className={loading ? "animate-spin" : ""} />
           </button>
        </div>
        
        <div className="glass overflow-hidden rounded-lg shadow-xl min-h-[400px]">
          {error ? (
              <div className="flex flex-col items-center justify-center h-64 text-red-500 gap-2">
                  <AlertCircle size={40}/> <p>{error}</p>
              </div>
          ) : (
          <>
          <table className="w-full text-left border-collapse">
            <thead className="bg-[var(--accent-color)]/10 text-[var(--text-color)] uppercase text-[10px] font-bold tracking-wider">
              <tr>
                <th className="p-4 border-b border-[var(--glass-border)]">Номер</th>
                {isAdmin ? (
                    // Колонка Клиент (Только админ)
                    <th className="p-4 border-b border-[var(--glass-border)]">Клиент</th>
                ) : (
                    // Колонка Дата (Только юзер)
                    <th className="p-4 border-b border-[var(--glass-border)]">Дата</th>
                )}
                <th className="p-4 border-b border-[var(--glass-border)]">Сумма / Оплата</th>
                <th className="p-4 border-b border-[var(--glass-border)]">Статус</th>
                <th className="p-4 border-b border-[var(--glass-border)] text-right">Действия</th>
              </tr>
            </thead>
            <tbody className="text-sm text-[var(--text-color)]">
              {orders.length === 0 ? (
                  <tr><td colSpan="5" className="p-10 text-center opacity-30">Список заказов пуст</td></tr>
              ) : currentItems.map((o) => (
                <tr key={o.id} className="hover:bg-[var(--accent-color)]/5 border-b border-[var(--glass-border)] last:border-0 group transition-colors">
                  
                  {/* ID */}
                  <td className="p-4 font-mono text-[var(--accent-color)] font-bold">#{o.order_number || o.id}</td>
                  
                  {/* КЛИЕНТ (АДМИН) ИЛИ ДАТА (ЮЗЕР) */}
                  {isAdmin ? (
                    <td className="p-4">
                      <div className="font-bold text-xs">{o.username || 'ID: ' + o.user_id}</div>
                      <div className="text-[9px] opacity-50">{o.user_email}</div>
                      {o.telegram_chat_id && <span className="text-[9px] text-blue-400 opacity-70">TG Linked</span>}
                    </td>
                  ) : (
                    <td className="p-4 text-xs opacity-60 font-mono">
                        {new Date(o.created_at).toLocaleDateString()}
                    </td>
                  )}
                  
                  {/* ОПЛАТА */}
                  <td className="p-4">
                    <div className="font-mono font-bold">{o.total} ₽</div>
                    <div className={`text-[10px] uppercase font-bold mt-1 w-fit px-1.5 rounded ${o.payment_status==='paid' ? 'bg-green-500/20 text-green-500' : 'bg-yellow-500/20 text-yellow-500'}`}>
                      {o.payment_status === 'paid' ? 'ОПЛАЧЕНО' : 'ОЖИДАНИЕ'}
                    </div>
                  </td>

                  {/* СТАТУС (РАЗНЫЙ РЕНДЕР) */}
                  <td className="p-4">
                    {isAdmin ? renderStatusPipeline(o.status) : renderStatusBadge(o.status)}
                  </td>

                  {/* КНОПКИ */}
                  <td className="p-4 text-right flex justify-end gap-2 items-center">
                    
                    {/* Кнопка "Глаз" для всех */}
                    <button onClick={() => setViewData(o)} title="Детали" className="p-2 rounded hover:bg-[var(--accent-color)] hover:text-black transition-colors text-gray-400">
                      <Eye size={18}/>
                    </button>
                    
                    {/* КНОПКИ УПРАВЛЕНИЯ (ТОЛЬКО ДЛЯ АДМИНА) */}
                    {isAdmin && o.status !== 'completed' && o.status !== 'cancelled' && (
                      <>
                        {/* ОТМЕНА */}
                        <button 
                          onClick={() => cancelOrder(o.id)}
                          title="Отменить заказ"
                          className="p-2 rounded text-red-500 hover:bg-red-500 hover:text-white border border-red-500/30 hover:border-red-500 transition-colors"
                        >
                          <XCircle size={18} />
                        </button>

                        {/* ВПЕРЕД */}
                        <button 
                          onClick={() => advanceStatus(o.id, o.status)}
                          className="flex items-center gap-1 bg-[var(--accent-color)] text-black px-3 py-1.5 rounded text-[10px] font-bold uppercase tracking-wide hover:bg-white transition-all shadow-lg shadow-[var(--accent-color)]/20"
                        >
                           {o.status === 'placed' ? 'В РАБОТУ' : (o.status === 'processing' ? 'ОТПРАВИТЬ' : 'ЗАВЕРШИТЬ')}
                           <ArrowRight size={10} className="ml-1 opacity-70"/>
                        </button>
                      </>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          
          {/* ПАГИНАЦИЯ */}
          <div className="flex justify-between items-center p-4 border-t border-[var(--glass-border)] bg-[var(--input-bg)]">
             <button onClick={() => setCurrentPage(p => Math.max(1, p - 1))} disabled={currentPage === 1} className="p-2 disabled:opacity-30 hover:text-[var(--accent-color)]"><ChevronLeft/></button>
             <span className="text-xs font-mono">СТР. {currentPage} / {totalPages}</span>
             <button onClick={() => setCurrentPage(p => Math.min(totalPages, p + 1))} disabled={currentPage === totalPages} className="p-2 disabled:opacity-30 hover:text-[var(--accent-color)]"><ChevronRight/></button>
          </div>
          </>
          )}
        </div>
      </div>
      
      {/* МОДАЛКА ПРОСМОТРА (ОБЩАЯ) */}
      {viewData && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm p-4">
          <div className="glass p-6 w-full max-w-md relative border border-[var(--glass-border)] text-[var(--text-color)] rounded-lg shadow-2xl">
            <button onClick={() => setViewData(null)} className="absolute top-4 right-4 hover:text-[var(--accent-color)]"><X size={20}/></button>
            
            <div className="mb-6 text-center border-b border-[var(--glass-border)] pb-4">
              <h3 className="text-2xl font-black text-[var(--accent-color)]">ЗАКАЗ #{viewData.order_number || viewData.id}</h3>
              <p className="text-xs opacity-50 font-mono">{new Date(viewData.created_at).toLocaleString()}</p>
              
              {/* В модалке показываем пайплайн для красоты всем, или бейдж */}
              <div className="mt-4 flex justify-center scale-90">
                  {isAdmin ? renderStatusPipeline(viewData.status) : renderStatusBadge(viewData.status)}
              </div>
            </div>

            <div className="space-y-4 text-sm">
                {isAdmin && (
                    <div className="flex justify-between border-b border-[var(--glass-border)] pb-2">
                        <span className="opacity-50">Клиент</span>
                        <div className="text-right">
                            <span className="font-bold block">{viewData.username}</span>
                            <span className="text-[10px] opacity-50">{viewData.user_email}</span>
                        </div>
                    </div>
                )}
                
                <div className="bg-[var(--input-bg)] p-3 rounded border border-[var(--glass-border)]">
                   <span className="text-[10px] opacity-50 uppercase block mb-1">Состав заказа:</span>
                   <p className="font-mono text-xs whitespace-pre-wrap">{viewData.content}</p>
                </div>

                <div className="grid grid-cols-2 gap-3">
                   <div className="p-2 bg-[var(--input-bg)] rounded border border-[var(--glass-border)]">
                      <span className="text-[10px] opacity-50 block uppercase">Метод оплаты</span>
                      {viewData.payment_method || 'Карта'}
                   </div>
                   <div className="p-2 bg-[var(--input-bg)] rounded border border-[var(--glass-border)]">
                      <span className="text-[10px] opacity-50 block uppercase">Статус оплаты</span>
                      <span className={`font-bold ${viewData.payment_status==='paid'?'text-green-500':'text-yellow-500'}`}>
                         {viewData.payment_status === 'paid' ? 'ОПЛАЧЕНО' : 'ОЖИДАЕТ'}
                      </span>
                   </div>
                </div>

                <div className="p-2 bg-[var(--input-bg)] rounded border border-[var(--glass-border)]">
                   <span className="text-[10px] opacity-50 block uppercase">Адрес доставки</span>
                   {viewData.delivery_address || 'Нет данных'}
                </div>
                
                <div className="flex justify-between items-center pt-2 text-xl font-black text-[var(--accent-color)] border-t border-[var(--glass-border)] mt-2">
                   <span>ИТОГО:</span>
                   <span>{viewData.total} ₽</span>
                </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
export default OrdersTable;