import React from 'react';
import styled from 'styled-components';

const Pogoda = () => {
  return (
    <StyledWrapper>
      <div className="weather-card">
        
        {/* Верхняя часть: Основная инфо */}
        <div className="main-info">
          <div className="icon-container">
             {/* SVG Иконка: Облачно с прояснениями */}
             <svg viewBox="0 0 64 64" className="weather-icon">
                <circle cx="20" cy="20" r="12" fill="#f59e0b" />
                <path d="M46,46 H26 c-3.3,0-6-2.7-6-6 s2.7-6,6-6 h2.5 c0.9-4.3,4.7-7.5,9.1-7.5 c5.2,0,9.4,4.2,9.4,9.4 c0,0.3,0,0.7-0.1,1 H46 c2.8,0,5,2.2,5,5 S48.8,46,46,46z" fill="#fff" stroke="#94a3b8" strokeWidth="2" strokeLinejoin="round"/>
             </svg>
          </div>
          <div className="text-container">
             <div className="temp">-18°C</div>
             <div className="city">Ангарск</div>
             <div className="desc">Иркутская обл.</div>
          </div>
        </div>

        {/* Нижняя часть: Детали (Раскрывается при наведении) */}
        <div className="details">
           
           <div className="detail-item">
              <svg viewBox="0 0 24 24" className="detail-icon">
                 <path fill="#3b82f6" d="M12 2.69l5.66 5.66a8 8 0 1 1-11.31 0z" />
              </svg>
              <span>78%</span>
              <small>Влага</small>
           </div>

           <div className="detail-item">
              <svg viewBox="0 0 24 24" className="detail-icon">
                 <path fill="#94a3b8" d="M4 11h13.5c.8 0 1.5.7 1.5 1.5s-.7 1.5-1.5 1.5H4v-3zm0-7h13.5c.8 0 1.5.7 1.5 1.5S18.3 7 17.5 7H4V4z" />
              </svg>
              <span>4 м/с</span>
              <small>Ветер</small>
           </div>

           <div className="detail-item">
              <svg viewBox="0 0 24 24" className="detail-icon">
                 <circle cx="12" cy="12" r="9" fill="none" stroke="#f43f5e" strokeWidth="2"/>
                 <path d="M12 12 L14 14" stroke="#f43f5e" strokeWidth="2" strokeLinecap="round"/>
              </svg>
              <span>752</span>
              <small>мм рт.ст</small>
           </div>

        </div>
      </div>
    </StyledWrapper>
  );
}

const StyledWrapper = styled.div`
  /* Стили контейнера */
  .weather-card {
    width: 200px;
    height: 90px; /* Компактная высота по умолчанию */
    background: rgba(255, 255, 255, 0.9);
    border-radius: 20px;
    padding: 15px;
    box-shadow: 0 10px 30px rgba(0,0,0,0.2);
    border: 1px solid rgba(255,255,255,0.5);
    transition: all 0.4s cubic-bezier(0.175, 0.885, 0.32, 1.275);
    overflow: hidden;
    cursor: default;
    display: flex;
    flex-direction: column;
    gap: 15px;
  }

  /* При наведении карточка растет */
  .weather-card:hover {
    height: 180px;
    width: 220px;
    transform: translateY(-10px);
    background: #fff;
  }

  /* Верхняя часть */
  .main-info {
    display: flex;
    align-items: center;
    gap: 15px;
  }

  .weather-icon {
    width: 50px;
    height: 50px;
  }

  .text-container {
    display: flex;
    flex-direction: column;
  }

  .temp {
    font-size: 24px;
    font-weight: 800;
    color: #1e293b;
    line-height: 1;
  }

  .city {
    font-size: 14px;
    font-weight: 700;
    color: #475569;
    margin-top: 4px;
  }

  .desc {
    font-size: 10px;
    color: #94a3b8;
  }

  /* Детали (скрыты или сжаты по умолчанию) */
  .details {
    display: flex;
    justify-content: space-between;
    opacity: 0;
    transform: translateY(20px);
    transition: all 0.3s ease;
    border-top: 1px solid #e2e8f0;
    padding-top: 15px;
  }

  .weather-card:hover .details {
    opacity: 1;
    transform: translateY(0);
  }

  .detail-item {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 4px;
  }

  .detail-icon {
    width: 20px;
    height: 20px;
  }

  .detail-item span {
    font-size: 12px;
    font-weight: 700;
    color: #334155;
  }

  .detail-item small {
    font-size: 9px;
    color: #64748b;
  }
`;

export default Pogoda;
