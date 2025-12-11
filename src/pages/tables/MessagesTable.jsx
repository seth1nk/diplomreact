import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { Eye, Mail, User, Shield, RefreshCw, AlertCircle, X, ChevronLeft, ChevronRight } from 'lucide-react';
import ActionMenu from '../../components/ActionMenu';
const API_URL = 'https://test.apt142.ru';
const MessagesTable = ({ user }) => {
  const [msgs, setMsgs] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [viewData, setViewData] = useState(null);
  const [currentPage, setCurrentPage] = useState(1);
  const itemsPerPage = 10;
  const isAdmin = 
    user?.role === 'admin' || 
    user?.email === 'admin@mail.ru' || 
    user?.name === 'seth1nk';
  useEffect(() => {
    fetchMessages();
    const interval = setInterval(fetchMessages, 10000); 
    return () => clearInterval(interval);
  }, []);
  const fetchMessages = async () => {
    const token = localStorage.getItem('token');
    if (!token) return;
    try {
        setLoading(true);
        const res = await axios.get(`${API_URL}/admin/messages`, {
            headers: { Authorization: `Bearer ${token}` }
        });
        const sorted = res.data.sort((a, b) => new Date(b.created_at) - new Date(a.created_at));
        setMsgs(sorted);
        setError(null);
    } catch (e) {
        console.error("Fetch error:", e);
        if (e.response && e.response.status === 403) {
             setError("У вас нет прав администратора для просмотра всех сообщений.");
        } else if (e.response && e.response.status === 404) {
             setError("API '/admin/messages' не найден. Проверьте index.js.");
        } else {
             setError("Не удалось загрузить сообщения. Проверьте сервер.");
        }
    } finally {
        setLoading(false);
    }
  };
  const handleDelete = async (id) => {
      if (!isAdmin) return alert("Доступ запрещен");
      if (window.confirm("Удалить сообщение?")) {

          alert("Функция удаления пока не настроена на сервере.");
      }
  };
  const indexOfLastItem = currentPage * itemsPerPage;
  const indexOfFirstItem = indexOfLastItem - itemsPerPage;
  const currentItems = msgs.slice(indexOfFirstItem, indexOfLastItem);
  const totalPages = Math.ceil(msgs.length / itemsPerPage);
  const renderStatus = (m) => {
      if (m.is_admin) return <span className="text-[10px] font-bold text-blue-400 bg-blue-400/10 px-2 py-1 rounded border border-blue-400/20">ОТВЕТ</span>;
      if (m.is_read) return <span className="text-[10px] font-bold text-green-500 bg-green-500/10 px-2 py-1 rounded border border-green-500/20">ПРОЧИТАНО</span>;
      return <span className="text-[10px] font-bold text-yellow-500 bg-yellow-500/10 px-2 py-1 rounded border border-yellow-500/20">НОВОЕ</span>;
  };

  return (
    <div className="pt-28 pb-10 min-h-screen px-4">
      <div className="max-w-7xl mx-auto">
        
        {/* ЗАГОЛОВОК */}
        <div className="flex justify-between items-end mb-6 border-b border-[var(--glass-border)] pb-4">
            <div>
                <h2 className="text-3xl font-black text-[var(--accent-color)] uppercase tracking-widest">
                    ПОДДЕРЖКА / ЧАТ ({msgs.length})
                </h2>
            </div>
            
            <button 
                onClick={fetchMessages} 
                className="p-2 bg-[var(--accent-color)]/20 rounded hover:bg-[var(--accent-color)] hover:text-black transition-all"
            >
                <RefreshCw size={18} className={loading ? "animate-spin" : ""} />
            </button>
        </div>
        
        {/* ТАБЛИЦА */}
        <div className="glass overflow-hidden rounded-lg shadow-xl min-h-[400px]">
          
          {error ? (
              <div className="flex flex-col items-center justify-center h-64 text-red-500 gap-2">
                  <AlertCircle size={40}/>
                  <p className="text-sm font-bold">{error}</p>
              </div>
          ) : (
            <>
              <table className="w-full text-left border-collapse">
                <thead className="bg-[var(--accent-color)]/10 text-[var(--text-color)] uppercase text-[10px] font-bold tracking-wider">
                  <tr>
                    <th className="p-4 w-10">#</th>
                    <th className="p-4">Дата</th>
                    <th className="p-4">Отправитель</th>
                    <th className="p-4">Тема / Текст</th>
                    <th className="p-4">Статус</th>
                    <th className="p-4 text-right">Инфо</th>
                  </tr>
                </thead>
                <tbody className="text-sm text-[var(--text-color)]">
                  {msgs.length === 0 ? (
                     <tr>
                        <td colSpan="6" className="p-12 text-center opacity-30 text-lg">
                            {loading ? "Загрузка..." : "Сообщений пока нет"}
                        </td>
                     </tr>
                  ) : currentItems.map((m) => (
                    <tr key={m.id} className="hover:bg-[var(--accent-color)]/5 border-b border-[var(--glass-border)] last:border-0 transition-colors">
                      <td className="p-4 opacity-50"><Mail size={16} /></td>
                      <td className="p-4 text-xs font-mono opacity-70">
                          {new Date(m.created_at).toLocaleString()}
                      </td>
                      
                      <td className="p-4">
                        <div className="flex items-center gap-2">
                            <div className={`p-1 rounded ${m.is_admin ? 'text-blue-400 bg-blue-400/10' : 'text-[var(--text-color)] bg-white/10'}`}>
                                {m.is_admin ? <Shield size={14}/> : <User size={14}/>}
                            </div>
                            <div>
                                <div className={`font-bold ${m.is_admin ? 'text-blue-400' : ''}`}>
                                    {m.user_name || 'Аноним'}
                                </div>
                                <div className="text-[9px] opacity-40">{m.email}</div>
                            </div>
                        </div>
                      </td>

                      <td className="p-4 max-w-[300px]">
                          <div className="flex flex-col">
                              <span className="text-xs font-bold opacity-80 mb-1 truncate">{m.subject}</span>
                              <p className="truncate opacity-60 text-xs">{m.text}</p>
                          </div>
                      </td>

                      <td className="p-4">{renderStatus(m)}</td>

                      <td className="p-4 text-right flex justify-end gap-2 items-center">
                        <button onClick={() => setViewData(m)} className="p-2 hover:text-[var(--accent-color)] text-gray-400" title="Просмотреть">
                            <Eye size={18}/>
                        </button>
                        {/* Меню действий только для админа */}
                        {isAdmin && (
                            <ActionMenu 
                                onEdit={() => {}} 
                                onDelete={() => handleDelete(m.id)} 
                            />
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
              
              {/* ПАГИНАЦИЯ */}
              {totalPages > 1 && (
                <div className="flex justify-between items-center p-4 border-t border-[var(--glass-border)] bg-[var(--input-bg)]">
                    <button onClick={() => setCurrentPage(p => Math.max(1, p - 1))} disabled={currentPage === 1} className="p-2 hover:text-[var(--accent-color)] disabled:opacity-30"><ChevronLeft/></button>
                    <span className="text-xs font-mono">СТР. {currentPage} / {totalPages}</span>
                    <button onClick={() => setCurrentPage(p => Math.min(totalPages, p + 1))} disabled={currentPage === totalPages} className="p-2 hover:text-[var(--accent-color)] disabled:opacity-30"><ChevronRight/></button>
                </div>
              )}
            </>
          )}
        </div>
      </div>

      {/* МОДАЛКА ПРОСМОТРА */}
      {viewData && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm p-4">
          <div className="glass p-6 w-full max-w-lg relative border border-[var(--glass-border)] text-[var(--text-color)] rounded-xl shadow-2xl">
            <button onClick={() => setViewData(null)} className="absolute top-4 right-4 hover:text-red-500 transition-colors">
                <X size={20}/>
            </button>
            
            <div className="flex items-center gap-3 mb-4 pb-4 border-b border-[var(--glass-border)]">
                <div className={`w-12 h-12 rounded-full flex items-center justify-center text-xl font-bold ${viewData.is_admin ? 'bg-blue-500 text-white' : 'bg-[var(--accent-color)] text-black'}`}>
                    {viewData.user_name ? viewData.user_name[0].toUpperCase() : '?'}
                </div>
                <div>
                    <h3 className="font-bold text-lg">{viewData.subject}</h3>
                    <p className="text-xs opacity-50">{viewData.email} • {new Date(viewData.created_at).toLocaleString()}</p>
                </div>
            </div>

            <div className="bg-[var(--input-bg)] p-4 rounded-xl border border-[var(--glass-border)] text-sm whitespace-pre-wrap leading-relaxed max-h-[50vh] overflow-y-auto custom-scroll">
                {viewData.text}
            </div>
            
            <div className="mt-4 flex justify-between text-[10px] opacity-40 font-mono">
                <span>IP: {viewData.ip || 'Скрыт'}</span>
                <span>ID: {viewData.id}</span>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default MessagesTable;