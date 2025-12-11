import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { Shield, User, Plus, X, Eye, ChevronLeft, ChevronRight, AlertCircle } from 'lucide-react';
import ActionMenu from '../../components/ActionMenu';

const API_URL = 'https://test.apt142.ru';

const UsersTable = ({ user }) => {
  const [users, setUsers] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [viewData, setViewData] = useState(null);
  const [formData, setFormData] = useState({ id: null, name: '', email: '', password: '', role: 'user', status: 'active' });
  
  // ПАГИНАЦИЯ
  const [currentPage, setCurrentPage] = useState(1);
  const itemsPerPage = 10;

  // Проверка прав (админ видит кнопки управления, обычный юзер - только список)
  const isAdmin = user?.role === 'admin' || user?.email === 'admin@mail.ru';

  useEffect(() => { 
      fetchUsers(); 
  }, []);

  const fetchUsers = async () => { 
      setLoading(true);
      try {
          // !!! ГЛАВНОЕ ИСПРАВЛЕНИЕ: ДОБАВЛЕН ЗАГОЛОВОК С ТОКЕНОМ !!!
          const token = localStorage.getItem('token');
          const res = await axios.get(`${API_URL}/users`, {
              headers: { Authorization: `Bearer ${token}` }
          });
          setUsers(res.data);
          setError(null);
      } catch (e) {
          console.error("Ошибка загрузки пользователей:", e);
          setError("Не удалось загрузить список.");
      } finally {
          setLoading(false);
      }
  };

  const handleDelete = async (id) => { 
      if (!isAdmin) return alert("Только для админов");
      if (window.confirm('Уничтожить пользователя?')) { 
          try {
            await axios.delete(`${API_URL}/admin/users/${id}`, { headers: { Authorization: `Bearer ${localStorage.getItem('token')}` } }); 
            fetchUsers(); 
          } catch(e) { alert("Ошибка удаления"); }
      }
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    const token = localStorage.getItem('token');
    const headers = { Authorization: `Bearer ${token}` };
    try {
      if (formData.id) await axios.put(`${API_URL}/admin/users/${formData.id}`, formData, { headers });
      else await axios.post(`${API_URL}/admin/users`, formData, { headers });
      setIsModalOpen(false); 
      fetchUsers();
    } catch (e) { alert('Ошибка сохранения'); }
  };

  // ЛОГИКА ПАГИНАЦИИ
  const indexOfLastItem = currentPage * itemsPerPage;
  const indexOfFirstItem = indexOfLastItem - itemsPerPage;
  const currentItems = users.slice(indexOfFirstItem, indexOfLastItem);
  const totalPages = Math.ceil(users.length / itemsPerPage);

  return (
    <div className="pt-28 pb-10 min-h-screen px-4">
      <div className="max-w-7xl mx-auto">
        <div className="flex justify-between items-end mb-6 border-b border-[var(--glass-border)] pb-4">
          <div>
            <h2 className="text-3xl font-black text-[var(--accent-color)] tracking-widest uppercase">ПОЛЬЗОВАТЕЛИ({users.length})</h2>
          </div>
          
          {/* Кнопка "Создать" только для админа */}
          {isAdmin && (
            <button 
                onClick={() => { setFormData({ id: null, name: '', email: '', password: '', role: 'user', status: 'active' }); setIsModalOpen(true); }} 
                className="btn-neon px-4 py-2 text-xs font-bold flex items-center gap-2"
            >
                <Plus size={16}/> НОВЫЙ
            </button>
          )}
        </div>

        <div className="glass overflow-hidden rounded-lg shadow-xl min-h-[400px]">
          {loading ? (
             <div className="p-10 text-center opacity-50">Загрузка списка пользователей...</div>
          ) : error ? (
             <div className="p-10 text-center text-red-500 flex flex-col items-center gap-2"><AlertCircle/> {error}</div>
          ) : (
          <>
            <table className="w-full text-left border-collapse">
                <thead className="bg-[var(--accent-color)]/10 text-[var(--text-color)] uppercase text-[10px] font-bold tracking-wider">
                <tr>
                    <th className="p-4">ID</th>
                    <th className="p-4">Имя</th>
                    <th className="p-4">Роль</th>
                    <th className="p-4">Статус</th>
                    <th className="p-4 text-right">Действия</th>
                </tr>
                </thead>
                <tbody className="text-sm text-[var(--text-color)]">
                {currentItems.map((u) => (
                    <tr key={u.id} className="hover:bg-[var(--accent-color)]/5 border-b border-[var(--glass-border)] last:border-0">
                    <td className="p-4 font-mono opacity-50">#{u.id}</td>
                    <td className="p-4 flex items-center gap-3">
                        <div className={`p-1 rounded ${u.role==='admin'?'text-red-500':'text-blue-500'}`}>
                            {u.role==='admin'?<Shield size={16}/>:<User size={16}/>}
                        </div>
                        <div className="flex flex-col">
                            <span className="font-bold">{u.name}</span>
                            <span className="text-[10px] opacity-50">{u.email}</span>
                        </div>
                    </td>
                    <td className="p-4 uppercase text-xs font-bold opacity-70">{u.role}</td>
                    <td className="p-4">
                        <span className={`px-2 py-0.5 rounded text-[10px] uppercase border ${u.status==='active'?'border-green-500 text-green-500':'border-red-500 text-red-500'}`}>
                            {u.status}
                        </span>
                    </td>
                    <td className="p-4 text-right flex justify-end gap-2 items-center">
                        <button onClick={() => setViewData(u)} className="p-2 text-gray-400 hover:text-[var(--accent-color)] transition-colors">
                            <Eye size={18}/>
                        </button>
                        {/* Меню действий только для админа */}
                        {isAdmin && (
                            <ActionMenu 
                                onEdit={() => { setFormData({...u, password: ''}); setIsModalOpen(true); }} 
                                onDelete={() => handleDelete(u.id)} 
                            />
                        )}
                    </td>
                    </tr>
                ))}
                </tbody>
            </table>
            
            {/* PAGINATION CONTROLS */}
            {users.length > 0 && (
                <div className="flex justify-between items-center p-4 border-t border-[var(--glass-border)] bg-[var(--input-bg)]">
                    <button onClick={() => setCurrentPage(p => Math.max(1, p - 1))} disabled={currentPage === 1} className="p-2 disabled:opacity-30 hover:text-[var(--accent-color)]"><ChevronLeft/></button>
                    <span className="text-xs font-mono">СТРАНИЦА {currentPage} ИЗ {totalPages}</span>
                    <button onClick={() => setCurrentPage(p => Math.min(totalPages, p + 1))} disabled={currentPage === totalPages} className="p-2 disabled:opacity-30 hover:text-[var(--accent-color)]"><ChevronRight/></button>
                </div>
            )}
          </>
          )}
        </div>
      </div>
      
      {/* MODAL CREATE/EDIT */}
      {isModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm p-4">
          <div className="glass p-6 w-full max-w-md relative border border-[var(--accent-color)] rounded-xl">
            <button onClick={() => setIsModalOpen(false)} className="absolute top-4 right-4 text-[var(--text-color)] hover:text-red-500"><X size={20}/></button>
            <h3 className="text-xl font-bold text-[var(--accent-color)] mb-4">{formData.id?'РЕДАКТИРОВАТЬ':'СОЗДАТЬ'}</h3>
            <form onSubmit={handleSubmit} className="flex flex-col gap-3">
              <input className="bg-[var(--input-bg)] border border-[var(--glass-border)] p-2 rounded text-[var(--text-color)] focus:border-[var(--accent-color)] outline-none" placeholder="Name" value={formData.name} onChange={e=>setFormData({...formData,name:e.target.value})} required/>
              <input className="bg-[var(--input-bg)] border border-[var(--glass-border)] p-2 rounded text-[var(--text-color)] focus:border-[var(--accent-color)] outline-none" placeholder="Email" value={formData.email} onChange={e=>setFormData({...formData,email:e.target.value})} required/>
              {!formData.id && <input className="bg-[var(--input-bg)] border border-[var(--glass-border)] p-2 rounded text-[var(--text-color)] focus:border-[var(--accent-color)] outline-none" type="password" placeholder="Password" value={formData.password} onChange={e=>setFormData({...formData,password:e.target.value})} required/>}
              <div className="flex gap-2">
                  <select className="bg-[var(--input-bg)] border border-[var(--glass-border)] p-2 rounded text-[var(--text-color)] w-1/2 outline-none" value={formData.role} onChange={e=>setFormData({...formData,role:e.target.value})}>
                      <option value="user">User</option>
                      <option value="admin">Admin</option>
                  </select>
                  <select className="bg-[var(--input-bg)] border border-[var(--glass-border)] p-2 rounded text-[var(--text-color)] w-1/2 outline-none" value={formData.status} onChange={e=>setFormData({...formData,status:e.target.value})}>
                      <option value="active">Active</option>
                      <option value="banned">Banned</option>
                  </select>
              </div>
              <button className="btn-neon py-2 mt-2 font-bold rounded">СОХРАНИТЬ</button>
            </form>
          </div>
        </div>
      )}

      {/* MODAL VIEW DETAILS (Обновленный красивый вид) */}
      {viewData && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm p-4">
            <div className="glass p-6 w-full max-w-lg relative border border-[var(--glass-border)] text-[var(--text-color)] rounded-lg shadow-2xl">
            <button onClick={() => setViewData(null)} className="absolute top-4 right-4 hover:text-[var(--accent-color)]"><X size={20}/></button>
            
            <div className="flex items-center gap-4 mb-6 border-b border-[var(--glass-border)] pb-4">
                <div className="w-16 h-16 rounded-full bg-[var(--accent-color)]/20 flex items-center justify-center text-2xl font-bold text-[var(--accent-color)]">
                {viewData.name ? viewData.name[0].toUpperCase() : '?'}
                </div>
                <div>
                <h3 className="text-xl font-bold text-[var(--accent-color)]">{viewData.name}</h3>
                <p className="text-xs opacity-50 uppercase tracking-widest">{viewData.role}</p>
                </div>
            </div>

            <div className="grid grid-cols-2 gap-4 text-sm">
                <div className="bg-[var(--input-bg)] p-2 rounded border border-[var(--glass-border)]">
                <span className="text-[10px] opacity-50 block uppercase">Email</span>
                {viewData.email}
                </div>
                <div className="bg-[var(--input-bg)] p-2 rounded border border-[var(--glass-border)]">
                <span className="text-[10px] opacity-50 block uppercase">Телефон</span>
                {viewData.phone || 'Не указан'}
                </div>
                <div className="bg-[var(--input-bg)] p-2 rounded border border-[var(--glass-border)]">
                <span className="text-[10px] opacity-50 block uppercase">Статус</span>
                <span className={`font-bold ${viewData.status==='active'?'text-green-500':'text-red-500'}`}>{viewData.status}</span>
                </div>
                <div className="bg-[var(--input-bg)] p-2 rounded border border-[var(--glass-border)]">
                <span className="text-[10px] opacity-50 block uppercase">IP Адрес</span>
                <span className="font-mono">{viewData.ip || 'Нет данных'}</span>
                </div>
                <div className="bg-[var(--input-bg)] p-2 rounded border border-[var(--glass-border)]">
                <span className="text-[10px] opacity-50 block uppercase">Referral Code</span>
                <span className="font-mono text-xs">{viewData.referral_code}</span>
                </div>
                <div className="bg-[var(--input-bg)] p-2 rounded border border-[var(--glass-border)]">
                <span className="text-[10px] opacity-50 block uppercase">Последний вход</span>
                {viewData.last_login ? new Date(viewData.last_login).toLocaleDateString() : '-'}
                </div>
                <div className="col-span-2 bg-[var(--input-bg)] p-2 rounded border border-[var(--glass-border)]">
                <span className="text-[10px] opacity-50 block uppercase">Дата регистрации</span>
                {viewData.created_at ? new Date(viewData.created_at).toLocaleString() : '-'}
                </div>
            </div>
            </div>
        </div>
        )}
    </div>
  );
};

export default UsersTable;