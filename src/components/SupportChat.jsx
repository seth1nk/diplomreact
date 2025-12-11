import React, { useState, useEffect, useRef } from 'react';
import axios from 'axios';
import { Send, X, MessageSquare, User, Shield, RefreshCw, Check, CheckCheck } from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';

const API_URL = 'https://test.apt142.ru';

const SupportChat = ({ isOpen, onClose, user }) => {
  const [messages, setMessages] = useState([]);
  const [newMessage, setNewMessage] = useState('');
  
  // Для админа - список пользователей, написавших сообщения
  const [uniqueSenders, setUniqueSenders] = useState([]); 
  const [selectedEmail, setSelectedEmail] = useState(null); // Фильтр для админа (выбранный чат)
  const [loading, setLoading] = useState(false);
  
  // Проверка прав админа (по роли или имени)
  const isAdmin = user?.role === 'admin' || user?.name === 'seth1nk' || user?.name === 'SuperAdmin';
  
  const messagesEndRef = useRef(null);

  // --- ЗАГРУЗКА СООБЩЕНИЙ ---
  const fetchMessages = async () => {
    try {
      const token = localStorage.getItem('token');
      
      // Если админ - загружаем все сообщения
      if (isAdmin) {
          const res = await axios.get(`${API_URL}/messages`, {
              headers: { Authorization: `Bearer ${token}` }
          });
          const allMsgs = res.data;
          setMessages(allMsgs);

          // Извлекаем уникальных отправителей для списка контактов
          // (фильтруем тех, кто писал, исключая админские ответы)
          const senders = [];
          const seen = new Set();
          
          allMsgs.forEach(m => {
              // Если сообщение от юзера (не админ) и мы его еще не видели
              if (!m.is_admin && m.email && !seen.has(m.email)) {
                  seen.add(m.email);
                  senders.push({ name: m.user_name, email: m.email });
              }
          });
          setUniqueSenders(senders);
      } 
      // Если обычный юзер - загружаем только его сообщения (фильтр на сервере по email)
      else {
          const res = await axios.get(`${API_URL}/messages?email=${user.email}`, {
              headers: { Authorization: `Bearer ${token}` }
          });
          setMessages(res.data);

          // Если чат открыт, помечаем сообщения от админа как прочитанные
          if (isOpen) {
             await axios.post(`${API_URL}/messages/read`, { email: user.email }, {
                headers: { Authorization: `Bearer ${token}` }
             });
          }
      }
    } catch (e) {
      console.error("Ошибка загрузки сообщений:", e);
    }
  };

  // Автообновление сообщений каждые 3 секунды
  useEffect(() => {
    if (isOpen) {
      fetchMessages();
      const interval = setInterval(fetchMessages, 3000); 
      return () => clearInterval(interval);
    }
  }, [isOpen, isAdmin, user]);

  // Скролл вниз при новом сообщении
  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages, selectedEmail, isOpen]);

  // --- ОТПРАВКА СООБЩЕНИЯ ---
  const handleSendMessage = async (e) => {
    e.preventDefault();
    if (!newMessage.trim()) return;

    setLoading(true);
    try {
        // Если пишет АДМИН -> используем специальный эндпоинт ответа (эмуляция ответа бота)
        // Или используем /contact, но сервер должен понять, что это админ.
        // В текущей реализации сервера /contact всегда ставит is_admin = FALSE.
        // Поэтому для админа лучше использовать /api/bot/reply (как будто бот ответил), 
        // ЧТОБЫ СОХРАНИЛОСЬ КАК is_admin = TRUE.
        
        if (isAdmin && selectedEmail) {
            await axios.post(`${API_URL}/api/bot/reply`, {
                email: selectedEmail,
                text: newMessage
            });
        } else {
            // Если пишет ЮЗЕР
            await axios.post(`${API_URL}/contact`, {
                name: user.name,
                email: user.email,
                message: newMessage
            });
        }
        
        setNewMessage('');
        fetchMessages(); // Обновляем список сразу
    } catch (error) {
        console.error('Ошибка отправки:', error);
    } finally {
        setLoading(false);
    }
  };

  // --- ФИЛЬТРАЦИЯ СООБЩЕНИЙ ДЛЯ ОТОБРАЖЕНИЯ ---
  // Если админ: показываем только сообщения выбранного юзера (и ответы ему)
  // Если юзер: показываем все загруженные (они уже отфильтрованы сервером)
  const displayedMessages = isAdmin 
    ? (selectedEmail ? messages.filter(m => m.email === selectedEmail) : [])
    : messages;

  return (
    <AnimatePresence>
      {isOpen && (
        <motion.div 
            initial={{ opacity: 0, y: 20, scale: 0.9 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, y: 20, scale: 0.9 }}
            className="fixed bottom-24 right-4 md:right-8 w-[90vw] md:w-[400px] h-[550px] z-50 glass border border-[var(--accent-color)] rounded-2xl shadow-2xl overflow-hidden flex flex-col"
        >
            {/* --- HEADER --- */}
            <div className="bg-[var(--accent-color)]/10 p-4 border-b border-[var(--glass-border)] flex justify-between items-center backdrop-blur-md">
                <div className="flex items-center gap-2 text-[var(--accent-color)]">
                    <MessageSquare size={20} />
                    <h3 className="font-black tracking-widest text-sm uppercase">
                        {isAdmin ? 'ПАНЕЛЬ ПОДДЕРЖКИ' : 'ЧАТ С ПОДДЕРЖКОЙ'}
                    </h3>
                </div>
                <div className="flex items-center gap-2">
                    <button 
                        onClick={fetchMessages} 
                        className="text-[var(--text-color)] hover:text-[var(--accent-color)] hover:rotate-180 transition-all duration-500"
                        title="Обновить"
                    >
                        <RefreshCw size={16} />
                    </button>
                    <button 
                        onClick={onClose} 
                        className="text-[var(--text-color)] hover:text-red-500 transition-colors"
                        title="Закрыть"
                    >
                        <X size={20} />
                    </button>
                </div>
            </div>

            {/* --- BODY --- */}
            <div className="flex-1 overflow-hidden relative bg-[var(--bg-color)]/95 flex flex-col">
                
                {/* --- СПИСОК ЮЗЕРОВ (ТОЛЬКО ДЛЯ АДМИНА) --- */}
                {isAdmin && !selectedEmail && (
                    <div className="w-full h-full overflow-y-auto custom-scroll p-2 space-y-2">
                        <p className="text-xs text-center opacity-50 my-2 uppercase font-bold tracking-wider">Входящие обращения</p>
                        
                        {uniqueSenders.length === 0 && (
                            <div className="flex flex-col items-center justify-center h-40 opacity-30">
                                <MessageSquare size={40} />
                                <p className="mt-2 text-sm">Сообщений нет</p>
                            </div>
                        )}

                        {uniqueSenders.map((u) => (
                            <div 
                                key={u.email}
                                onClick={() => setSelectedEmail(u.email)}
                                className="p-3 glass rounded-xl cursor-pointer hover:bg-[var(--accent-color)]/10 transition-colors flex items-center gap-3 border border-[var(--glass-border)] group"
                            >
                                <div className="w-10 h-10 rounded-full bg-gradient-to-br from-blue-600 to-purple-600 flex items-center justify-center text-white text-sm font-bold shadow-lg group-hover:scale-110 transition-transform">
                                    {u.name ? u.name[0].toUpperCase() : '?'}
                                </div>
                                <div className="overflow-hidden flex-1">
                                    <div className="font-bold text-sm text-[var(--text-color)] truncate flex justify-between">
                                        {u.name}
                                        <span className="text-[9px] opacity-40 font-normal">Открыть</span>
                                    </div>
                                    <div className="text-[10px] opacity-50 truncate font-mono">{u.email}</div>
                                </div>
                            </div>
                        ))}
                    </div>
                )}

                {/* --- ОКНО ЧАТА --- */}
                {(!isAdmin || selectedEmail) && (
                    <div className="w-full flex flex-col h-full">
                        
                        {/* Кнопка "Назад" для админа */}
                        {isAdmin && (
                            <button 
                                onClick={() => setSelectedEmail(null)} 
                                className="text-xs text-[var(--text-color)] w-full py-2 bg-black/20 hover:bg-black/40 border-b border-[var(--glass-border)] flex items-center justify-center gap-2 transition-colors"
                            >
                                ← Назад к списку диалогов ({selectedEmail})
                            </button>
                        )}

                        <div className="flex-1 overflow-y-auto p-4 space-y-4 custom-scroll">
                            {displayedMessages.length === 0 && (
                                <div className="h-full flex flex-col items-center justify-center opacity-30 text-center select-none">
                                    <div className="w-16 h-16 bg-[var(--accent-color)]/20 rounded-full flex items-center justify-center mb-4">
                                        <MessageSquare size={32} className="text-[var(--accent-color)]"/>
                                    </div>
                                    <p className="text-sm font-bold">Напишите нам!</p>
                                    <p className="text-xs max-w-[200px]">Мы ответим в ближайшее время. История сохраняется.</p>
                                </div>
                            )}
                            
                            {displayedMessages.map((msg) => {
                                // ОПРЕДЕЛЯЕМ КТО ПИСАЛ
                                // is_admin=true -> Поддержка
                                // is_admin=false -> Юзер
                                
                                // Если я Админ -> Мои сообщения это is_admin=true
                                // Если я Юзер -> Мои сообщения это is_admin=false
                                const isMe = isAdmin ? msg.is_admin : !msg.is_admin;

                                return (
                                    <div key={msg.id} className={`flex ${isMe ? 'justify-end' : 'justify-start'}`}>
                                        <div 
                                            className={`max-w-[85%] p-3 rounded-2xl text-sm relative border shadow-sm ${
                                                isMe 
                                                ? 'bg-[var(--accent-color)] text-black border-[var(--accent-color)] rounded-tr-none text-right' 
                                                : 'bg-[#1a1a20] text-white border-gray-700 rounded-tl-none text-left'
                                            }`}
                                        >
                                            {/* Имя отправителя (если не я) */}
                                            {!isMe && (
                                                <p className={`text-[10px] mb-1 font-bold uppercase tracking-wider ${isAdmin ? 'text-[var(--accent-color)]' : 'opacity-50'}`}>
                                                    {msg.is_admin ? 'Поддержка' : msg.user_name}
                                                </p>
                                            )}
                                            
                                            <p className="whitespace-pre-wrap leading-relaxed">{msg.text}</p>
                                            
                                            {/* Время и Галочки */}
                                            <div className={`flex items-center gap-1 mt-1 ${isMe ? 'justify-end opacity-70' : 'justify-start opacity-40'}`}>
                                                <span className="text-[9px] font-mono">
                                                    {new Date(msg.created_at).toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'})}
                                                </span>
                                                
                                                {/* Галочки показываем только для СВОИХ сообщений */}
                                                {isMe && (
                                                    msg.is_read 
                                                    ? <CheckCheck size={14} className="text-blue-600" strokeWidth={3} /> // Прочитано (Синие)
                                                    : <Check size={14} strokeWidth={2} /> // Отправлено (Серые/Черные)
                                                )}
                                            </div>
                                        </div>
                                    </div>
                                );
                            })}
                            <div ref={messagesEndRef} />
                        </div>

                        {/* --- INPUT --- */}
                        <form onSubmit={handleSendMessage} className="p-3 bg-black/40 border-t border-[var(--glass-border)] flex gap-2 backdrop-blur-sm">
                            <input 
                                type="text"
                                value={newMessage}
                                onChange={(e) => setNewMessage(e.target.value)}
                                placeholder="Введите сообщение..."
                                disabled={isAdmin && !selectedEmail} // Админ не может писать, не выбрав чат
                                className="flex-1 bg-[var(--input-bg)] border border-[var(--glass-border)] rounded-xl px-4 py-3 text-sm text-[var(--text-color)] focus:border-[var(--accent-color)] outline-none transition-all disabled:opacity-50 disabled:cursor-not-allowed"
                            />
                            <button 
                                type="submit" 
                                disabled={loading || (isAdmin && !selectedEmail)}
                                className="bg-[var(--accent-color)] text-black p-3 rounded-xl hover:bg-white hover:scale-105 transition-all shadow-lg shadow-[var(--accent-color)]/20 disabled:opacity-50 disabled:cursor-not-allowed disabled:shadow-none"
                            >
                                {loading ? <RefreshCw size={20} className="animate-spin"/> : <Send size={20} />}
                            </button>
                        </form>
                    </div>
                )}
            </div>
        </motion.div>
      )}
    </AnimatePresence>
  );
};

export default SupportChat;