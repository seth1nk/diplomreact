import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { Eye, X, Terminal, AlertTriangle, ChevronLeft, ChevronRight } from 'lucide-react';

const LogsTable = ({ user }) => {
  const [logs, setLogs] = useState([]);
  const [viewData, setViewData] = useState(null);
  
  // ПАГИНАЦИЯ
  const [currentPage, setCurrentPage] = useState(1);
  const itemsPerPage = 10;
  
  const isAdmin = user?.role === 'admin';

  useEffect(() => {
    if (isAdmin) axios.get('https://test.apt142.ru/logs', { headers: { Authorization: `Bearer ${localStorage.getItem('token')}` } }).then(res => setLogs(res.data));
  }, [isAdmin]);

  const indexOfLastItem = currentPage * itemsPerPage;
  const indexOfFirstItem = indexOfLastItem - itemsPerPage;
  const currentItems = logs.slice(indexOfFirstItem, indexOfLastItem);
  const totalPages = Math.ceil(logs.length / itemsPerPage);

  if (!isAdmin) return <div className="h-screen flex items-center justify-center text-red-500 gap-4"><AlertTriangle size={48}/><h1 className="text-3xl font-black">ACCESS DENIED</h1></div>;

  return (
    <div className="pt-28 pb-10 min-h-screen px-4 font-mono">
      <div className="max-w-7xl mx-auto">
        <h2 className="text-3xl font-black text-red-500 mb-6 uppercase tracking-widest border-b border-red-900/30 pb-4 flex items-center gap-3"><Terminal/> SYSTEM LOGS ({logs.length})</h2>
        <div className="glass bg-black/90 overflow-hidden rounded-lg shadow-xl border-red-900/30">
          <table className="w-full text-left border-collapse text-xs text-gray-400">
            <thead className="bg-red-900/20 text-red-500 uppercase font-bold">
              <tr><th className="p-3">Time</th><th className="p-3">User</th><th className="p-3">Method</th><th className="p-3">Route</th><th className="p-3">Status</th><th className="p-3 text-right">View</th></tr>
            </thead>
            <tbody>
              {currentItems.map((l) => (
                <tr key={l.id} className="hover:bg-red-900/10 border-b border-red-900/20">
                  <td className="p-3 opacity-60">{new Date(l.timestamp).toLocaleTimeString()}</td>
                  <td className="p-3 text-gray-200">{l.username}</td>
                  <td className="p-3 font-bold">{l.method}</td>
                  <td className="p-3">{l.url}</td>
                  <td className={`p-3 font-bold ${l.status_code>=400?'text-red-500':'text-green-500'}`}>{l.status_code}</td>
                  <td className="p-3 text-right"><button onClick={() => setViewData(l)}><Eye size={14} className="hover:text-white"/></button></td>
                </tr>
              ))}
            </tbody>
          </table>
          <div className="flex justify-between items-center p-4 border-t border-red-900/30 bg-black">
             <button onClick={() => setCurrentPage(p => Math.max(1, p - 1))} disabled={currentPage === 1} className="p-2 disabled:opacity-30 hover:text-red-500"><ChevronLeft/></button>
             <span className="text-xs font-mono text-red-500">PAGE {currentPage} OF {totalPages}</span>
             <button onClick={() => setCurrentPage(p => Math.min(totalPages, p + 1))} disabled={currentPage === totalPages} className="p-2 disabled:opacity-30 hover:text-red-500"><ChevronRight/></button>
          </div>
        </div>
      </div>
      {viewData && (<div className="fixed inset-0 z-50 flex items-center justify-center bg-black/90 backdrop-blur-sm p-4 text-gray-300 font-mono"><div className="bg-[#111] p-6 w-full max-w-2xl relative border border-red-900"><button onClick={() => setViewData(null)} className="absolute top-4 right-4 text-red-500"><X size={20}/></button><h3 className="text-lg font-bold text-red-500 mb-4">LOG DETAIL #{viewData.id}</h3><pre className="text-xs bg-black p-4 overflow-auto max-h-96 border border-gray-800">{JSON.stringify(viewData, null, 2)}</pre></div></div>)}
    </div>
  );
};
export default LogsTable;