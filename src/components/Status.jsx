import React from 'react';
import styled from 'styled-components';

const Status = ({ status, date }) => {
  // Определяем активный шаг на основе статуса
  const getStatusIndex = (s) => {
    if (s === 'new') return 1;
    if (s === 'processing') return 2;
    if (s === 'shipping') return 3;
    if (s === 'completed') return 4;
    return 0;
  };

  const currentStep = getStatusIndex(status || 'new');

  return (
    <StyledWrapper>
      <div className="stepper-box">
        {/* STEP 1: PLACED */}
        <div className={`stepper-step ${currentStep > 1 ? 'stepper-completed' : currentStep === 1 ? 'stepper-active' : 'stepper-pending'}`}>
          <div className="stepper-circle">{currentStep > 1 ? '✓' : '1'}</div>
          <div className="stepper-line" />
          <div className="stepper-content">
            <div className="stepper-title">Размещен</div>
            <div className="stepper-status">{currentStep > 1 ? 'Готово' : currentStep === 1 ? 'Сейчас' : 'Ожидание'}</div>
            <div className="stepper-time">{date || '---'}</div>
          </div>
        </div>

        {/* STEP 2: PROCESSING */}
        <div className={`stepper-step ${currentStep > 2 ? 'stepper-completed' : currentStep === 2 ? 'stepper-active' : 'stepper-pending'}`}>
          <div className="stepper-circle">{currentStep > 2 ? '✓' : '2'}</div>
          <div className="stepper-line" />
          <div className="stepper-content">
            <div className="stepper-title">В обработке</div>
            <div className="stepper-status">{currentStep > 2 ? 'Готово' : currentStep === 2 ? 'В работе' : 'Ожидание'}</div>
          </div>
        </div>

        {/* STEP 3: SHIPPING */}
        <div className={`stepper-step ${currentStep > 3 ? 'stepper-completed' : currentStep === 3 ? 'stepper-active' : 'stepper-pending'}`}>
          <div className="stepper-circle">{currentStep > 3 ? '✓' : '3'}</div>
          <div className="stepper-content">
            <div className="stepper-title">Доставка / Установка</div>
            <div className="stepper-status">{currentStep > 3 ? 'Готово' : currentStep === 3 ? 'В пути' : 'Ожидание'}</div>
          </div>
        </div>
      </div>
    </StyledWrapper>
  );
}

const StyledWrapper = styled.div`
  .stepper-box {
    background-color: var(--card-bg, #1e293b);
    border: 1px solid var(--glass-border, rgba(255,255,255,0.1));
    border-radius: 12px;
    padding: 20px;
    width: 100%;
    color: var(--text-color, #fff);
  }

  .stepper-step { display: flex; margin-bottom: 20px; position: relative; }
  .stepper-step:last-child { margin-bottom: 0; }

  .stepper-line {
    position: absolute; left: 15px; top: 35px; bottom: -25px; width: 2px;
    background-color: rgba(255,255,255,0.1); z-index: 1;
  }
  .stepper-step:last-child .stepper-line { display: none; }

  .stepper-circle {
    width: 32px; height: 32px; border-radius: 50%;
    display: flex; align-items: center; justify-content: center;
    margin-right: 16px; z-index: 2; font-weight: bold; font-size: 14px;
    transition: all 0.3s;
  }

  .stepper-completed .stepper-circle { background-color: #22c55e; color: white; }
  .stepper-active .stepper-circle { border: 2px solid #3b82f6; color: #3b82f6; background: rgba(59, 130, 246, 0.1); }
  .stepper-pending .stepper-circle { border: 2px solid #64748b; color: #64748b; }

  .stepper-content { flex: 1; }
  .stepper-title { font-weight: 600; font-size: 14px; margin-bottom: 2px; }
  .stepper-status { font-size: 12px; opacity: 0.7; }
  .stepper-time { font-size: 11px; opacity: 0.5; margin-top: 2px; }
`;

export default Status;
